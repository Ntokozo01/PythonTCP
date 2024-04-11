# MDUDUZI NDLOVU: NDLMDU011
# SPHIWE NYONI: NYNSPH001
# MATSHEPO MATHOTO: MTHMAT043

from socket import *
import os
import hashlib
import time
import threading
import concurrent.futures

BUFFERSIZE = 4096
SEPARATOR = "<SEPARATOR>"
# Dictionary - {Filename: fileInfo[]}
# FileInfo = [Visibility, Protected, Key, hexValue, fileSize, clientName, Password, visibilityCode]
dictFiles = {"File_sample.txt": [
    "N", "Y", "0000", "63636", "12626", "ndlmdu011", "Mdu_01", "MN123"]}
numClients = 0 # Number of Clients currently connected


# Using the hashlib library, opens the file from the server storage, reads its contents and
#     gets its hasher hex value and return it
def get_hex(fname):
    hasher = hashlib.md5()
    openfile = open(fname, "rb")
    content = openfile.read()
    hasher.update(content)
    return hasher.hexdigest()


# Accepts the hex value of the file from server and that from the uploading client's storage and
#  checks if the values are the same or not and return True if same, else False.
def check_sum(serverFile, sentFile):
    if serverFile == sentFile:
        return True
    else:
        return False


# Creates and opens the file in the server storage and receives the read bytes (lines) from the client file
#  using the server-client connection and writes them to the server file then save and close the file.
def receiveFile(conn, filename):
    file = open(filename, "wb")
    print("Receiving file...")

    line = conn.recv(BUFFERSIZE)
    bytesRecv = BUFFERSIZE
    text = "Received: " + str(round(bytesRecv/1024, 0)) + " KB"

    while (line != b"DONE!"):
        conn.send(text.encode())
        file.write(line)
        # print(line)
        line = conn.recv(BUFFERSIZE)
        bytesRecv += BUFFERSIZE
        text = "Received: " + str(round(bytesRecv/1024, 0)) + " KB"

    file.close()

# Checks if the file requested for download is in the server or available for download, checks if it needs an encryption key,
# asks and receives it from the client then checks if the key is accepted or not. If the file was not found in the server or
#  the key was not accepted, sends a failed message to client and returns 0, else it send Granted permission and return 1
def checkAndSend(conn, dictFiles, filename):

    fileInfo = getFileInfo(filename, dictFiles)
    if len(fileInfo) >= 4:
        pass
    else:
        conn.send(b"Failed!")
        return 0

    protected = fileInfo[1]
    encryptkey = fileInfo[2]

    # [Protected, hasher value]
    info = protected + SEPARATOR + fileInfo[4]
    conn.send(info.encode())
    decryptkey = conn.recv(BUFFERSIZE).decode()

    if protected == "Y":
        if decryptkey == encryptkey:  # The provided decrption key matches with the shared-key
            conn.send("Granted".encode())
        else:
            conn.send("DENIED".encode())
            return 0
    else:
        conn.send("Granted".encode())

    return 1

#  Opens and reads the file from the server storage and sends the lines of bytes of data to the client and sends "DONE!" when
#   finished sending all the bytes of the file
def sendingFile(conn, filename):

    print("Opening and reading file")
    file = open(filename, "rb")

    line = file.read(BUFFERSIZE)
    # print(line)
    while (line):
        empty = conn.recv(BUFFERSIZE)
        conn.send(line)
        line = file.read(BUFFERSIZE)

    file.close()
    conn.send(b"DONE!")

# Sends the File names of all the visible files in the server line by line to the client
def sendingList(conn, dictFiles):
    ##
    if len(dictFiles) < 1:
        conn.send("DONE!".encode())
        return 0

    for fname in dictFiles:
        privacy = dictFiles.get(fname)
        # privacy = [Visibility, Protected, Key, hexValue, fileSize, clientName, Password, VisibilityCode]
        fname = fname + SEPARATOR 

        if privacy[1] == "Y":
            fname += " (Protected)"

        if privacy[0] == "Y":
            conn.send(fname.encode())
            empty = conn.recv(BUFFERSIZE).decode()

    conn.send("DONE!".encode())
    return 1

# Checks if the file is saved in the server (contained in dictFiles)
# or not disregarding the case sensitivity of the filename from dictFiles
def searchFile(filename, dictFiles):
    for fname in dictFiles:
        if fname.upper() == filename.upper():
            return True

    return False

# Get the FileInfo of the file if it is in dictFiles saved with the key of that filename disregarding the case of the name,
# else sends an empty list [] if the file is not found
def getFileInfo(filename, dictFiles):
    for fname in dictFiles:
        if fname.upper() == filename.upper():
            return dictFiles[fname]

    return []

# Checks the correct case of the filename it saved by in dictFiles and returns it
def getSavedName(filename, dictFiles):
    for fname in dictFiles:
        # e.g. fname == file1.txt    filename == File1.txt
        if fname.upper() == filename.upper():
            return fname

    return filename

# Checks if there already is a file in the server with the same filename and renames the file to a new name of which is
# not present in the server and returns the new filename of the to be saved as if doesn't exists
def checkFilename(filename, dictFiles):
    count = 1
    period = filename.find(".")
    bname = filename
    ext = ""

    if period > 0:
        bname = filename[0:period]
        ext = filename[period:]

    # e.g. file1.txt --> file(1).txt --> file(2).txt
    while searchFile(filename, dictFiles):
        filename = bname + "(" + str(count) + ")" + ext
        count += 1

    return filename

def saveInfoToFile(filename, fileInfo):
    fList = "File_list.txt"
    fexists = os.path.exists(fList)

    #f = open(fList, "a")
    f = ""
    if fexists:
        f = open(fList, "a")
    else:
        f = open(fList, "w") 

    string = "##"
    line = filename + "[]" + string.join(fileInfo)
    print(line, file=f)
    f.close()

def retrieveFromFile(dictFiles):
    fList = "File_list.txt"

    if os.path.exists(fList):
        f = open(fList, "r")
        line = f.readline()

        while line:
            lstFile = line.split("[]")
            filename = lstFile[0]
            fileInfo = lstFile[1]
            fileInfo = fileInfo.split("##")
            dictFiles.update({filename: fileInfo})
            line = f.readline()
        f.close()
    
    

# This allows each client in each thread to run the at the same time doing same or different tasks. The thread
# will wait for clients call and accept them
def compute(sock, threadNum):
    global dictFiles, numClients
   ## sock.listen(5)
    print("\nThread", threadNum, " started.")
    conn, address = sock.accept()

    try:  # Reduce client system errors to shutting the server down
        print("\nConnection with client opened (thread", threadNum, "):", address[0])
        numClients += 1
        print("Number of connected clients:", numClients)

        count = 1
        REQUEST = conn.recv(BUFFERSIZE).decode()

        if REQUEST == "U":  # UPLOAD, receive the file from the client and save to server

            print("An UPLOAD REQUEST was received")
            conn.send("UPLOAD request received".encode())

            filename = conn.recv(BUFFERSIZE).decode()

            # Checks if filename exists in the server and renames to a new non-existing one
            filename = checkFilename(filename, dictFiles)
            text = "Saving file as \"" + filename + "\""
            conn.send(text.encode())

            # open write the file data and save the file to the server
            receiveFile(conn, filename)

            conn.send("Ready to receive file Info".encode())
            msg = conn.recv(BUFFERSIZE).decode()

            fileInfo = msg.split(SEPARATOR)

            serverFile = get_hex(filename)  # this received file hex value
            clientFile = fileInfo[3]  # uploader hex value

            text = ""
            # check if file transimmission was successful without corrupting the file

            if check_sum(serverFile, clientFile):
                saveInfoToFile(filename, fileInfo)
                dictFiles.update({filename: fileInfo})
                text = "Successful"
            else:
                # File corrupted, remove it from the server storage
                os.remove(filename)
                text = "Failed"

            print("DONE! receiving file")
            conn.send(text.encode())

        elif REQUEST == "D":  # DOWNLOAD file requested, send the requested file to the user
            print("A DOWNLOAD REQUEST was received")

            conn.send("Send file name".encode())
            filename = conn.recv(BUFFERSIZE).decode()
            # correct case of character of the file
            filename = getSavedName(filename, dictFiles)

            # Checks for the file if present in the server and access permissions and return results
            result = checkAndSend(conn, dictFiles, filename)

            if result == 0:  # Client not permitted to download file or file was not found
                pass
            else:
                # Send file data to the client
                sendingFile(conn, filename)

                fileInfo = dictFiles.get(filename)
                # get hasher value of uploader file version
                serverFile = fileInfo[3]
                msg = conn.recv(BUFFERSIZE).decode()
                # send the hasher value to the user
                conn.send(serverFile.encode())

                print('DONE! sending')

        elif REQUEST == "V":  # VIEW AVAILABLE FILES
            print("A VIEW REQUEST was received")

            # Send the file names of all available files for viewing
            sendingList(conn, dictFiles)

            print("File list has been sent")

        elif REQUEST == "H":  # VIEW HIDDEN FILES
            print("Hidden Files requested")
            conn.send("Request Received".encode())

            vCode = conn.recv(BUFFERSIZE).decode()  # Visibility file code

            if len(dictFiles) < 1:
                conn.send("DONE!".encode())
                pass

            for fname in dictFiles:
                privacy = dictFiles.get(fname)
                # privacy = [Visibility, Protected, Key, hexValue, fileSize, clientName, Password, VisibilityCode]

                if privacy[1] == "Y":  # Add protected keyword next to filename for encrypted files
                    fname = fname + " (Protected)"

                # Send the file names belonging to the given visibility code
                if (privacy[0] == "N") and (privacy[7] == vCode):
                    conn.send(fname.encode())
                    empty = conn.recv(BUFFERSIZE).decode()

            conn.send("DONE!".encode())

        elif REQUEST == "O":
            conn.send("SEND USER DATA".encode())

            userData = conn.recv(BUFFERSIZE).decode()
            userData = userData.split(SEPARATOR)
            clientUsername = userData[0]
            clientPassword= userData[1]

            lstFiles = ""
            countF = 0
            for fname in dictFiles:
                fileInfo = dictFiles.get(fname)

                if fileInfo[5] == clientUsername and fileInfo[6] == clientPassword:
                    countF += 1
                    s = fname
                    if (fileInfo[1] == "Y"):
                        s += " (Protected)"
                    
                    lstFiles += str(countF) + ". " + s + "\n"
            conn.send(lstFiles.encode())
                

        elif REQUEST == "I":  # send the Info of the requested file
            print("File info request received")
            conn.send("Send File name".encode())

            filename = conn.recv(BUFFERSIZE).decode()

            fileInfo = getFileInfo(filename, dictFiles)
            print(fileInfo)
            if len(fileInfo) == 0:
                conn.send("File not found".encode())
            else:
                tCreated = os.path.getctime(filename)
                dateCreated = time.ctime(tCreated)

                tModified = os.path.getmtime(filename)
                dateModified = time.ctime(tModified)

                line = "File info for the file \"" + filename + "\":" + \
                    "\n" + "Protected: " + str(fileInfo[1] == "Y") + \
                    "\n" + "File size: " + f"{int(fileInfo[4]):,}" + " bytes" \
                    "\n" + "Uploaded by: " + fileInfo[5] + \
                    "\n" + "Uploaded at: " + str(dateModified) + \
                    "\n" + "Created at: " + str(dateCreated)
                conn.send(line.encode())

        elif REQUEST == "R":  # REMOVE AND DELETE FILE from the system
            conn.send("SendFilename".encode())

            msg = conn.recv(BUFFERSIZE).decode()
            # [filename, clientUsername, clientPassword]
            msg = msg.split(SEPARATOR)

            filename = msg[0]
            fileInfo = getFileInfo(filename, dictFiles)
            # get the correct case characters of the filename in the dictFiles
            fname = getSavedName(filename, dictFiles)

            if len(fileInfo) == 0:  # File was not found
                conn.send("Failed File Not found".encode())
            else:
                # Check if the uploader details match with this client's details
                if (fileInfo[5] == msg[1]) and (fileInfo[6] == msg[2]):
                    os.remove(filename)
                    del dictFiles[fname]
                    conn.send("File removed".encode())
                else:
                    # The current user profile is not the one that uploaded the file
                    conn.send(
                        "You don't have access to delete this file".encode())

        elif REQUEST == "C":  # CLOSE the connection with the client properly
            conn.send("Connection closed".encode())
            print("\nConnection with client closed:", address[0])
            numClients -= 1
            print("Number of connected clients:", numClients)
            conn.close()
            return 1

        else:  # INVALID REQUEST
            conn.send(("Invalid Request! " + REQUEST).encode())
            print("Invalid Request!", REQUEST)

        # Close connection and allow another client to connect
        print("Connection closed with client:", address[0])
        print("Thread", threadNum, "finished running.")
        numClients -= 1
        conn.close()

    except Exception as e:
        print(e)
        # Close the connection if error occurred on the client
        print("Interupt, Connection closed with client:", address[0])
        print("Thread", threadNum, "finished running.")
        numClients -= 1
        conn.close()

def main():
    global numClients
    HOST = "NDLMDU011"  # ('196.47.211.222', 60391)
    PORT = 120

    sock = socket(AF_INET, SOCK_STREAM)
    sock.bind((HOST, PORT))

    # The maximum number of threads or clients to access the server per time.
    # Since we using a PC as a server this was an adequate number to not kill our laptops, lol 
    MAX_CLIENTS = 1

    retrieveFromFile(dictFiles)
    
    print("Server is ready to receive")
    sock.listen(MAX_CLIENTS)

    numThreads = 0
    threadNumber = 0
    # The Server once turn on we Assume it will be running "forever"
    while True:
        # Creates 5 threads to each handle a client and run the compute method. When one thread finishes running
        # and is dead, a new thread is created to wait for another client 
        if numThreads <= MAX_CLIENTS:
            numThreads +=1
            threadNumber += 1
            #t1 = threading.Thread(target=compute, args=(sock, threadNumber))
            #t1.start()
            compute(sock,threadNumber)
        
        # Get the number of currently running threads
        numThreads = threading.active_count()
    
if __name__ == "__main__":
    main()

