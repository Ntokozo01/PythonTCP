import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from tkinter import simpledialog
from tkinter import messagebox

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
window = tk.Tk()
window.title("File Management System")
#window.geometry("500x500")

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
            progress_bar.step(10)
            print("Uploading...", f"{kilobytes:,.2f}",
                  "KB of", f"{(filesize/1024):,.2f}", "KB")
            window.update_idletasks()
            lapse += 10

        sock.recv(BUFFERSIZE).decode()
        bytesSent += BUFFERSIZE
        line = file.read(BUFFERSIZE)

    print("Uploading...", f"{(filesize/1024):,.2f}",
          "KB of", f"{(filesize/1024):,.2f}", "KB")
    progress_bar['value'] = 100
    window.update_idletasks()
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
        key = simpledialog.askstring("Key Request", "The file you want to download is protected by key.\nEnter the key to gain access:")
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

    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((serverHostname, serverPortNo))    

    if REQUEST == "H":  # View HIDDEN files from the server of a specified visibility code
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
    
def upload_request():
    serverHostname = ent_server_name.get()
    serverPortNo = int(ent_server_port.get())
    
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((serverHostname, serverPortNo))
    
    filename = ent_filename.get()
    filename = filename.strip("\"")
    fExists = os.path.exists(filename)

    if not fExists:
        return 1

    filesize = os.path.getsize(filename)
    fname = os.path.basename(filename)
    
    fileInfo = ""

    # Get the file access permissions and info
    visible = visibility_str.get()

    vCode = "0000"  # default file visibility code
    if visible[0:1] == "Y":
        vCode = ent_visibility_code.get()

    protected = protection_str.get()
    print(protected)

    encryptkey = "0000"  # default key
    if protected[0:1] == "Y":
        encryptkey = ent_encryption.get()

    print("Calculating validation key...")
    # calculate the hasher of the file to be uploaded
    hexFile = get_hex(filename)
    fileInfo += SEPARATOR + hexFile
    
    fileInfo += SEPARATOR + str(filesize)
    REQUEST = "U"

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
    fileInfo += SEPARATOR + username + SEPARATOR + password + SEPARATOR + vCode
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

def download_request():
    serverHostname = ent_server_name.get()
    serverPortNo = int(ent_server_port.get())
    
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((serverHostname, serverPortNo))
    
    REQUEST = "D"
    sock.send(REQUEST.encode())
    print("From server:", sock.recv(BUFFERSIZE).decode())
    filename = combo_box.get()
    filename = filename.strip("\"")
    fname = os.path.basename(filename)
    sock.send(fname.encode())

    # Check for file permissions and privacy from the server to download file, if granted download the file and save to the
    # requested path supplied with the filename
    
    to_save_path = save_file(fname)
    result = checkAndDownload(sock, to_save_path)

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

def view_request():
    serverHostname = ent_server_name.get()
    serverPortNo = int(ent_server_port.get())
    
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((serverHostname, serverPortNo))
    
    REQUEST = "V"
    sock.send(REQUEST.encode())
    print("Receiving the file list...")

    line = sock.recv(BUFFERSIZE).decode()
    count = 0
    files = []
    while line != "DONE!":  # Receive the names of the available files from server and displays them
        count += 1
        sock.send("Receiving..".encode())
        line_split = line.split(SEPARATOR)
        files.append(line_split[0])
        print(str(count) + ".", line_split[0] + line_split[1])
        line = sock.recv(BUFFERSIZE).decode()

    if count == 0:
        print("There are no available files for viewing!")
    else:
        print("Available files displayed.")
        
    combo_box['values'] = files
    combo_box.set(files[0]) 
    
def display_fileinfo():
    serverHostname = ent_server_name.get()
    serverPortNo = int(ent_server_port.get())
    
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((serverHostname, serverPortNo))
    
    REQUEST = "I"
    sock.send(REQUEST.encode())
    prompt = sock.recv(BUFFERSIZE).decode()  # request ack

    filename = combo_box.get()
    fname = os.path.basename(filename)
    sock.send(fname.encode())

    # Receive and display the file info if file exists on the server
    txt_fileinfo.delete("1.0", tk.END)
    line = sock.recv(BUFFERSIZE).decode()
    txt_fileinfo.insert(tk.END,line)
    
def remove_request():
    confirmation = messagebox.askyesno("Confirmation", "Are your sure you want to proceed?")
    if not confirmation:
        return 1
    
    serverHostname = ent_server_name.get()
    serverPortNo = int(ent_server_port.get())
    
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((serverHostname, serverPortNo))
    REQUEST = "R"
    
    filename = combo_box.get()
    filename = filename.strip("\"")
    fname = os.path.basename(filename)

    # Pass the filename and the user info requesting to remove the file from the server
    line = fname + SEPARATOR + username + SEPARATOR + password

    sock.send(REQUEST.encode())  # Send remove request
    ack = sock.recv(BUFFERSIZE).decode()  # request acknowlegdement

    sock.send(line.encode())
    print(sock.recv(BUFFERSIZE).decode())  # Results of the request

    
def open_file_dialog(ent_filename):
    filename = filedialog.askopenfilename()
    ent_filename.delete(0, tk.END)
    if filename:
        ent_filename.insert(0,filename)
        
def save_file(filename):
    file_path = filedialog.asksaveasfilename(defaultextension="", filetypes=[("All files", "*.*")], initialfile=filename)
    #if file_path:
    #    with open(file_path, "w") as file:
    #        file.write("Hello, World!")
    return file_path

username = "Samuel" #input("Enter your profile username:\n>> ")
password =  "SAMUEL11" #input("Enter your user profile password:\n>> ")

frm_server = tk.Frame(window, relief=tk.SUNKEN,borderwidth=2)
frm_server.pack(fill=tk.X)

lbl_server_name = tk.Label(frm_server, text="Server Name:")
ent_server_name = tk.Entry(frm_server, width="25")
lbl_server_name.pack(side=tk.LEFT) #.grid(row=0, column= 0, sticky="e")
ent_server_name.pack(side=tk.LEFT) #.grid(row=0,column=1)

lbl_server_port = tk.Label(frm_server, text="Port Number:")
ent_server_port = tk.Spinbox(frm_server, width="15",from_=0, to=10000)
lbl_server_port.pack(side=tk.LEFT) #.grid(row=0, column=2, sticky="e")
ent_server_port.pack(side=tk.LEFT) #.grid(row=0,column=3)

ent_server_name.insert(0, "NDLMDU011")
ent_server_port.insert(tk.END, "120")

frm_upload = tk.Frame(window, relief=tk.GROOVE, borderwidth=2)
frm_upload.pack(fill=tk.BOTH)

label_font = ("Arial", 12, "bold")
lbl_upload_header = tk.Label(frm_upload, text="FILE UPLOAD:", font=label_font)
lbl_upload_header.pack(fill=tk.BOTH, pady=10)

frm_filename = tk.Frame(frm_upload, relief=tk.FLAT, borderwidth=1)
frm_filename.pack(fill=tk.BOTH, side=tk.TOP)

lbl_filename = tk.Label(frm_filename, text="Filename:")
ent_filename = tk.Entry(frm_filename, width="20")
lbl_filename.pack(fill=tk.X, side=tk.LEFT) #.grid(row=0, column= 0, sticky="e")
ent_filename.pack(fill=tk.X, side=tk.LEFT,expand=True) #.grid(row=0,column=1)

btn_choose_file = tk.Button(frm_filename, text="Choose File", command=lambda: open_file_dialog(ent_filename))
btn_choose_file.pack(fill=tk.X, side=tk.RIGHT)

visibility_str = tk.StringVar(value="Yes")
protection_str = tk.StringVar(value="No")

chb_visibility = tk.Checkbutton(frm_upload,text="Is visible to all?", variable=visibility_str, onvalue="Yes", offvalue="No")
chb_visibility.pack(anchor=tk.W)

lbl_visibility_code = tk.Label(frm_upload, text="Visibility Code:")
ent_visibility_code= tk.Entry(frm_upload, width="20")
lbl_visibility_code.pack(anchor=tk.W)
ent_visibility_code.pack(fill=tk.X, expand=True)

chb_protection = tk.Checkbutton(frm_upload,text="Protect your file?", variable=protection_str, onvalue="Yes", offvalue="No")
chb_protection.pack(anchor=tk.W)

lbl_encryption = tk.Label(frm_upload, text="Encryption key:")
ent_encryption = tk.Entry(frm_upload, width="20")
lbl_encryption.pack(anchor=tk.W)
ent_encryption.pack(fill=tk.X, anchor=tk.E, expand=True )

btn_upload = tk.Button(frm_upload, text="UPLOAD", command=upload_request)
btn_upload.pack()

progress_bar = ttk.Progressbar(frm_upload, orient='horizontal', length=200, mode='determinate')
progress_bar.pack(pady=10)

frm_view = tk.Frame(window, relief=tk.GROOVE, borderwidth=2)
frm_view.pack(fill=tk.BOTH)

lbl_view_header = tk.Label(frm_view, text="VIEW FILES:", font=label_font)
lbl_view_header.pack(fill=tk.BOTH, pady=10)

btn_view = tk.Button(frm_view, text="VIEW", command=view_request)
btn_view.pack(fill=tk.X,padx=10, pady=10)

data = []
combo_box = ttk.Combobox(frm_view,values=data)
combo_box.pack(pady=20, fill=tk.X)

frm_button = tk.Frame(frm_view, relief=tk.RIDGE, borderwidth=2)
frm_button.pack(fill=tk.X, padx=10, pady=10)

frm_button.rowconfigure(0, weight=1, pad=10)
for i in range(3):
    frm_button.columnconfigure(i, weight=1, pad=10)

btn_displainfo = tk.Button(frm_button, text="DISPLAY FILE INFO", command=display_fileinfo)
btn_displainfo.grid(row=0, column=0, sticky="ew")

btn_download = tk.Button(frm_button, text="DOWNLOAD FILE", command=download_request)
btn_download.grid(row=0, column=1, sticky="ew")

btn_remove = tk.Button(frm_button, text="REMOVE FILE", command=remove_request)
btn_remove.grid(row=0, column=2, sticky="ew")

txt_fileinfo = tk.Text(frm_view, height=10)
txt_fileinfo.pack(fill=tk.X)



window.mainloop()
    
def main():
    global sock 

    username = "Samuel" #input("Enter your profile username:\n>> ")
    password =  "SAMUEL11" #input("Enter your user profile password:\n>> ")

    num_args = len(sys.argv)

    if num_args <= 3:
        # serverHostname = input("Enter the hostname of the server to connect to:\n>> ")
        # serverPortNo = eval(input("Enter the portNo. of the server to connect to:\n>> "))
        serverHostname = "NDLMDU011"  # "196.47.233.46"
        serverPortNo = 120
        #REQUEST = input("\n" + REQUEST_PROMPT + "\n>> ")
        #REQUEST = (REQUEST.upper())[0:1]

    elif num_args > 3:  # Read from command line arguments if adequate number of arguments were passed
        serverHostname = sys.argv[1]
        serverPortNo = int(sys.argv[2])
        REQUEST = (sys.argv[3])
        REQUEST = (REQUEST.upper())[0:1]

    
    
    
    """while True:
        result = execute(serverHostname,
                         serverPortNo, username, password)

        if result == 0:  # a call to exit the program was made
            break
    """ 

if __name__ == "__main__":
    main()
