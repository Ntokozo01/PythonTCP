# MDUDUZI NDLOVU : NDLMDU011

import platform
from socket import *
import os.path
import sys
import hashlib

BUFFERSIZE = 4096
SEPARATOR = "<SEPARATOR>"
REQUEST_PROMPT = "Enter a request to [U]pload File, [D]ownload File, [V]iew Files, [E]xit the Program or [M] for more requests:"
ADDITIONAL_REQUESTS = "Or to view [H]idden files, display file [I]nfo, [R]emove a file or [F]lush the terminal:"
REQUEST = "V"

# Using the hashlib library, opens and read the contents of the file, generates and returns a hasher string value of the content


def get_hex(name_of_file):
    hasher = hashlib.md5()
    openfile = open(name_of_file, "rb")
    content = openfile.read()
    hasher.update(content)
    return hasher.hexdigest()


# Open the file from the provided path and it exists, reads line of bytes from it and
# send lines to the server while printing the total bytes uploaded/sent to server and
# sends "DONE!" when sent all the bytes of the file
def uploadFile(sock, filename, filesize):
    file = open(filename, "rb")
    print('Sending file to server...')

    line = file.read(BUFFERSIZE)
    bytesSent = 0
    kilobytes = 0
    lapse = 0

    while (line):
        sock.send(line)
        perc = bytesSent / (filesize + 1) * 100
        kilobytes = bytesSent / 1024

        if int(perc) >= lapse:
            print("Uploading...", f"{kilobytes:,.2f}",
                  "KB of", f"{(filesize/1024):,.2f}", "KB")
            lapse += 10

        sock.recv(BUFFERSIZE).decode()
        bytesSent += BUFFERSIZE
        line = file.read(BUFFERSIZE)

    print("Uploading...", f"{(filesize/1024):,.2f}",
          "KB of", f"{(filesize/1024):,.2f}", "KB")
    sock.send(b"DONE!")
    file.close()

# Gets if the file requested for download is present in the server, returns 0 if failed,
# else receives the some info of the file from the server and check for access to download the file
# if access denied returns 0, else opens the file for download
def checkAndDownload(sock, filename):
    line = sock.recv(BUFFERSIZE)
    if line == b"Failed!":
        print("File \"" + filename + "\" is NOT in the server!")
        return 0

    info = line.decode()
    info = info.split(SEPARATOR)
    protected = info[0]
    filesize = int(info[1])

    if protected == "Y":
        key = input(
            "The file you want to download is protected by key. Enter the key to gain access:\n>> ")
        sock.send(key.encode())
    elif protected == "N":
        sock.send("0000".encode())

    # GRANTED OR DENIED ACCESS FOR A PROTECTED FILE
    fileAccess = sock.recv(BUFFERSIZE).decode()
    if fileAccess == "DENIED":
        print("Incorrect key. Request failed!")
        return 0
    else:
        print("Accepted")

    return downloadFile(filename, filesize, sock)


# Downloading file contents BUFFERSIZE bytes per time from the server and prints the total number
# of bytes downloaded for every tenth of the file size
def downloadFile(filename, filesize, sock):

    file = open(filename, "wb")
    print("Downloading file...")

    sock.send("Receiving..".encode())
    line = line = sock.recv(BUFFERSIZE)

    bytesSent = 0
    kilobytes = 0
    lapse = 0
    while (line != b"DONE!"):
        perc = bytesSent / (filesize + 1) * 100
        kilobytes = bytesSent / 1024

        # Lapse printing by 10%, 20%, 30% ... 100%
        if int(perc) >= lapse:
            print("Downloading...", f"{kilobytes:,.2f}",
                  "KB of", f"{(filesize/1024):,.2f}", "KB")
            lapse += 10
        file.write(line)
        sock.send("Receiving..".encode())

        line = sock.recv(BUFFERSIZE)
        bytesSent += BUFFERSIZE

    print("Downloading...", f"{(filesize/1024):,.2f}",
          "KB of", f"{(filesize/1024):,.2f}", "KB")
    file.close()
    return 1

# Called by the main method to execute a user request with server-client file transmission services


def execute(serverHostname, serverPortNo, username, password):
    global REQUEST
    # print(REQUEST)

    if REQUEST == "E":  # EXITS the application
        return 0

    if REQUEST == "M":  # Displays MORE prompt requests available
        REQUEST = input("\n" + REQUEST_PROMPT + "\n" +
                        ADDITIONAL_REQUESTS + "\n>> ").upper()
        REQUEST = REQUEST[0:1]

    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((serverHostname, serverPortNo))

    if REQUEST == "U":  # UPLOAD the file to server
        filename = input("Enter file name to send to server:\n>> ")
        filename = filename.strip("\"")
        fExists = os.path.exists(filename)

        tries = 1
        while fExists == False:
            print('"' + filename + '" does not exist')
            filename = input("Enter file name to send to server:\n>> ")
            filename = filename.strip("\"")
            fExists = os.path.exists(filename)
            tries += 1
            # Breaks and prompt the user for another REQUEST
            if tries == 3:
                print("Failed!")
                sock.close()
                REQUEST = "M"
                return 1

        filesize = os.path.getsize(filename)
        fname = os.path.basename(filename)

        # Get the file access permissions and info
        visible = input(
            "Should the file be visible to all users? Enter [Y]es / [N]o:\n>> ").upper()

        vCode = "0000"  # default file visibility code
        if visible[0:1] == "N":
            vCode = input("Enter the code to view the file by:\n>> ")

        protected = input(
            "Do you want to encrpt the file? Enter [Y]es / [N]o:\n>> ").upper()

        encryptkey = "0000"  # default key
        if protected[0:1] == "Y":
            encryptkey = input("Enter an encryption key:\n>> ")

        print("Calculating validation key...")
        # calculate the hasher of the file to be uploaded
        hexFile = get_hex(filename)

        sock.send(REQUEST.encode())  # Send an Upload request to the server

        # Request acknowledgement/ file name request
        print("From server:", sock.recv(BUFFERSIZE).decode())

        sock.send(fname.encode('utf-8'))  # Send the file name to the server
        # get the name the file is saved as in the server
        newFilename = sock.recv(BUFFERSIZE).decode()

        # Send the bytes of the file to the server
        uploadFile(sock, filename, filesize)

        print('DONE! sending')
        # requests the info and privacy details of the file
        msg = sock.recv(BUFFERSIZE).decode()

        # FileInfo = [Visibility, Protected, Encryption Key, hasher Value, FileSize, current user, user Password, visibilityCode]
        fileInfo = visible[0:1] + SEPARATOR + protected[0:1] + \
            SEPARATOR + encryptkey + SEPARATOR + \
            hexFile + SEPARATOR + str(filesize) + \
            SEPARATOR + username + SEPARATOR + password + SEPARATOR + vCode

        sock.send(fileInfo.encode())  # Sends the info and privacy of the file
        # Display to the user how the file is named and saved by on the server
        print("From Server:", newFilename)

        print("Server validating file transfer...")
        # Receive whether the file was success transmitted and saved on the server or not
        print("From Server:", sock.recv(BUFFERSIZE).decode())

    elif REQUEST == "D":  # DOWNLOAD
        sock.send(REQUEST.encode())

        print("From server:", sock.recv(BUFFERSIZE).decode())
        filename = input(
            "Enter the name of the file to Download from server:\n>> ")
        filename = filename.strip("\"")
        fname = os.path.basename(filename)
        sock.send(fname.encode())

        # Check for file permissions and privacy from the server to download file, if granted download the file and save to the
        # requested path supplied with the filename
        result = checkAndDownload(sock, filename)

        if result == 0:  # Access denied to download the file
            pass
        else:
            sock.send("Send hasher value".encode())
            # also the hasher value of the original file from uploader client
            serverFile = sock.recv(BUFFERSIZE).decode()
            # get hasher value of the downloaded file
            clientFile = get_hex(filename)

            # Check whether the file downloaded is the same as that was uploaded by the other client
            if serverFile == clientFile:
                print("File was successfully transmited and saved")
            else:
                print("The file was corrupted in transit")

    elif REQUEST == "V":  # VIEW the files that are available for viewing to all users
        sock.send(REQUEST.encode())
        print("Receiving the file list...")

        line = sock.recv(BUFFERSIZE).decode()
        count = 0
        while line != "DONE!":  # Receive the names of the available files from server and displays them
            count += 1
            sock.send("Receiving..".encode())
            line_split = line.split(SEPARATOR)
            print(str(count) + ".", line_split[0] + line_split[1])
            line = sock.recv(BUFFERSIZE).decode()

        if count == 0:
            print("There are no available files for viewing!")
        else:
            print("Available files displayed.")

    elif REQUEST == "H":  # View HIDDEN files from the server of a specified visibility code
        passCode = input("Enter the files visibility code:\n>> ")

        sock.send(REQUEST.encode())
        ack = sock.recv(BUFFERSIZE).decode()

        sock.send(passCode.encode())
        line = sock.recv(BUFFERSIZE).decode()

        if line == "NONE":
            print("DENIED")
            pass
        else:
            count = 1
            print("Printing all files under that visibility code...")
            while line != "DONE!":  # receive file names and print them out
                sock.send("Receiving..".encode())
                print(str(count) + ".", line)
                line = sock.recv(BUFFERSIZE).decode()
                count += 1

            print("Files of that visibility code displayed.")
    elif REQUEST == "O":
        sock.send(REQUEST.encode())

        userInfo = username + SEPARATOR + password
        sock.recv(BUFFERSIZE).decode()

        sock.send(userInfo.encode())

        print("Files uploaded by this user are:")
        print(sock.recv(BUFFERSIZE).decode())
        print("Your files have been displayed")

    elif REQUEST == "I":  # Display the file INFO of the requested file
        sock.send(REQUEST.encode())
        prompt = sock.recv(BUFFERSIZE).decode()  # request ack

        filename = input("Enter the name of the File:\n>> ")
        filename = filename.strip("\"")
        fname = os.path.basename(filename)
        sock.send(fname.encode())

        # Receive and display the file info if file exists on the server
        print()
        print(sock.recv(BUFFERSIZE).decode())

    elif REQUEST == "P":  # Profile username
        print("Your username is:", username)

    elif REQUEST == "R":  # REMOVE AND DELETE FILE
        filename = input("Enter the name of the file to remove:\n>> ")
        filename = filename.strip("\"")
        fname = os.path.basename(filename)

        # Pass the filename and the user info requesting to remove the file from the server
        line = fname + SEPARATOR + username + SEPARATOR + password

        sock.send(REQUEST.encode())  # Send remove request
        ack = sock.recv(BUFFERSIZE).decode()  # request acknowlegdement

        sock.send(line.encode())
        print(sock.recv(BUFFERSIZE).decode())  # Results of the request

    elif REQUEST == "F":  # FLUSH the terminal output
        try:
            os.system("cls")
        except:
            os.system("clear")

    elif REQUEST == "C":  # Close the server connection
        sock.send(REQUEST.encode())
        print("From Server:", sock.recv(BUFFERSIZE).decode())
        return 0

    else:  # INVALID REQUEST
        print("INVALID REQUEST")

    sock.close()

    REQUEST = input("\n" + REQUEST_PROMPT + "\n>> ")
    REQUEST = (REQUEST.upper())[0:1]


def main():
    global REQUEST

    username = input("Enter your profile username:\n>> ")
    password = input("Enter your user profile password:\n>> ")

    num_args = len(sys.argv)

    if num_args <= 3:
        # serverHostname = input("Enter the hostname of the server to connect to:\n>> ")
        # serverPortNo = eval(input("Enter the portNo. of the server to connect to:\n>> "))
        serverHostname = "NDLMDU011"  # "196.47.233.46"
        serverPortNo = 120
        REQUEST = input("\n" + REQUEST_PROMPT + "\n>> ")
        REQUEST = (REQUEST.upper())[0:1]

    elif num_args > 3:  # Read from command line arguments if adequate number of arguments were passed
        serverHostname = sys.argv[1]
        serverPortNo = int(sys.argv[2])
        REQUEST = (sys.argv[3])
        REQUEST = (REQUEST.upper())[0:1]

    while True:
        result = execute(serverHostname,
                         serverPortNo, username, password)

        if result == 0:  # a call to exit the program was made
            break


if __name__ == "__main__":
    main()
