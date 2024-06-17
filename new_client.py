import socket 
import ssl
import sys 
import errno 
import json
import pickle
from OpenSSL import crypto, SSL
import bcrypt
import xeddsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import pyAesCrypt
from os import stat, remove

from client_classes import User, Group, encodeKey, encodeSig

# defining the header length.
HEADER_LENGTH = 10

# defining the IP address and Port Number.
IP = "127.0.0.1"
PORT = 5000

# global variables 
user = None
client_socket = None
password = None
 
# ----------------------------------------------------------------------------------------

def oneWayTLSConnectionToServer():

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket = ssl.wrap_socket(client_socket,
                                    ca_certs="servercert.pem",
                                    cert_reqs=ssl.CERT_REQUIRED
                                    )

    client_socket.connect((IP, PORT))

    client_socket.setblocking(False)

    return client_socket


def twoWayTLSConnectToServer(username):
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client_socket = ssl.wrap_socket(client_socket,
                                ca_certs="servercert.pem",
                                certfile=f"{username}-TLScert.pem",
                                keyfile=f"{username}-TLSpriv.pem",
                                cert_reqs=ssl.CERT_REQUIRED)

    client_socket.connect((IP, PORT))

    # print(client_socket.getpeername())
    # print(client_socket.getpeercert())

    client_socket.setblocking(False)

    return client_socket


def cert_gen(keyFile, certFile, commonName=IP, organisationName='Self-signed', serialNumber=0, validityStart=0, validityEnd=10*365*24*60*60):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().O = organisationName
    cert.get_subject().CN = commonName
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(validityStart)
    cert.gmtime_adj_notAfter(validityEnd)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(certFile, "w+") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(keyFile, "w+") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")


def generateLTPersonalKeys():
    '''
    Move this function to client_classes file in the future
    '''
    identityKey = X25519PrivateKey.generate()
    signedPreKey = X25519PrivateKey.generate()
    preKeySignature = xeddsa.bindings.ed25519_priv_sign(priv=identityKey.private_bytes_raw(), msg=signedPreKey.public_key().public_bytes_raw())

    return identityKey, signedPreKey, preKeySignature


def sendMessage(payload):
    serialPayload = json.dumps(payload).encode('utf-8')
    header = f"{len(serialPayload):<{HEADER_LENGTH}}".encode('utf-8')

    client_socket.send(header + serialPayload)


def receive_message():
    try:
        """
        The received message header contains the message length, its size is defined, and the constant.
        """
        message_header = client_socket.recv(HEADER_LENGTH)

        """
        If the received data has no length then it means that the client has closed the connection. Hence, we will return False as no message was received.
        """
        if not len(message_header):
            return False

        # Convert header to an int value
        message_length = int(message_header.decode('utf-8').strip())

        # Returning an object of the message header and the data of the message data.
        return {'header': message_header, 'data': json.loads(client_socket.recv(message_length).decode('utf-8'))}

    except:
        return False


def createAccount():

    print('Alright! Let\'s create an account! \nPlease enter a username. ')
    username = input("Username: ")

    print(f'Your username is {username}. ')


    print('Great! Now, choose a password - it should be secure!')
    password = input('Password: ')

    print('Generating salt...')
    salt = bcrypt.gensalt(12, b"2b")

    # Save the salt locally
    with open(f'{username}-salt', 'wb') as file:
        file.write(salt)

    print('Great! Generating certificate for two-way TLS...')

    certTLS = cert_gen(keyFile=f"{username}-TLSpriv.pem", certFile=f"{username}-TLScert.pem")

    print('Generating long-term personal keys...')

    # Keys are generated as ordinary keys, not byte representations 
    IK, SPK, SIG = generateLTPersonalKeys()

    print('Constructing message for server...')

    # Server receives encoded versions of keys 
    userInfo = {
        'request' : 'create_account',
        'username' : username, 
        'password' : password, 
        'salt': encodeSig(salt),
        'certTLS' : certTLS,
        'IK' : encodeKey(IK),
        'SPK': encodeKey(SPK),
        'SIG': encodeSig(SIG)
    }

    print("Connecting to server...")

    global client_socket
    client_socket = oneWayTLSConnectionToServer()

    print("Sending information to server...")

    # send the data 
    sendMessage(userInfo)

    print("Awaiting response from the server - this may take some time, as passwords are hashed server-side...")

    responseReceived = False
    successfulCreation = False 
    while not responseReceived:
        try:
            # Decoding the received response - should implement timeout?
            response = receive_message()
            if not response:
                continue

            responseReceived = True

            responseInfo = response['data']
            if responseInfo['result'] == 'success':
                print('Account successfully created! \nPlease log in')
                successfulCreation = True

            else:
                print('Something went wrong... could not create account.')
                
        except IOError as e:
            # handling the normal error on nonblocking connections.
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print(e)
                print('Reading error: {}'.format(str(e)))
                sys.exit()

            # If we did not receive anything, then continue.
            continue

        
    client_socket.shutdown(socket.SHUT_RDWR)
    client_socket.close()

    if successfulCreation:

        # Create user object
        user = User(username=username, 
                    IK=IK, 
                    SPK=SPK, 
                    SIG=SIG
                    )

        # Special function which will convert keys as appropriate 
        user.saveData()

        # encrypt
        with open(f"{username}-data.pkl", "rb") as fIn:
            with open(f"{user.username}-data.pkl.aes", "wb") as fOut:
                pyAesCrypt.encryptStream(fIn, fOut, password)
        remove(f"{user.username}-data.pkl")


def login():

    username = input('Please enter your username: ')

    global password
    password = input('Please enter your password: ')

    with open(f'{username}-salt', 'rb') as file:
        salt = file.read()

    userInfo = {
        'request': 'login',
        'username': username,
        'password': password,
    }

    # For now - this will change with development of the CA separate from this program
    global client_socket
    client_socket = oneWayTLSConnectionToServer()

    sendMessage(userInfo)

    # looping over the received messages and printing them.
    responseReceived = False
    loggedIn = False 

    print('Logging in - this may take some time, as passwords are hashed server-side...')
    while not responseReceived:
        try:
            # Decoding the received response 
            response = receive_message()
            if not response:
                continue
            responseReceived = True

            responseInfo = response['data']
            if responseInfo['result'] == 'success':
                print('Successfully logged in!')

                loggedIn = True
            else:
                print('Something went wrong...')

        except IOError as e:
            # handling the normal error on nonblocking connections.
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print(e)
                print('Reading error: {}'.format(str(e)))
                sys.exit()

            # If we did not receive anything, then continue.
            continue

    if loggedIn:

        # load in the user data 
        global user 

        # decrypt
        with open(f"{username}-data.pkl.aes", "rb") as fIn:
            try:
                with open(f"{username}-data.pkl", "wb") as fOut:
                    # decrypt file stream
                    pyAesCrypt.decryptStream(fIn, fOut, password)
            except ValueError:
                # remove output file on error
                remove(f"{username}-data.pkl")

        with open(f"{username}-data.pkl", "rb") as file:
            user = pickle.load(file)

        '''
        function on user to load keys from bytes version 
        '''
        user.loadKeys()

        mainMenu()

    else:
        startupMenu()


def selectGroupchat():

    if len(user.groups) == 0:
        print("No groups to choose from...\n")
        mainMenu()

    else:
        # Display the user their groups 
        print('Available groupchats: ')
        for group in user.groups:
            print('- ' + group.groupName)

        # Take input from user of group name they want to enter 
        choice = input('Please enter the name of the groupchat to select it \n> ')

        # Find the group by name
        selectedGroup = None 
        for group in user.groups:
            if group.groupName == choice:
                selectedGroup = group

        # If choice is valid, enter the group
        if selectedGroup:
            print('Ok - entering group and updating state...')
            enterGroup(client_socket, selectedGroup)

        else:
            print("Invalid choice...")
            mainMenu()


def enterGroup(client_socket: socket, group: Group):
    quit = False

    # Printing all the previous messages in the chat 
    for message in group.messages:
        print(f"{message[0]} > {message[1]}")

    print("\n----------------------------\n")

    # Update state of group (receive messages)
    group.updateState(client_socket, user)

    noResponse = []
    for member in group.members:
        if not member.FDH:
            noResponse.append(member.username)

    if len(noResponse) > 0:
        print("Messages will not be sent to the following users, as they have not accepted their invitation:")
        for username in noResponse:
            print(f"- {username}")

    while not quit:
        # Getting user input.
        message = input(f'{user.username} > ')

        if message == '/quit':
            quit = True
            continue
            
        elif message == '/invite':
            username = input("Who do you want to invite? ")

            group.addMember(user, username, client_socket)
            continue

        # Sending the non-empty message.
        if message:
            group.sendMessage(user, client_socket, message)

            # Add sent message to messages list 
            group.messages.append((user.username, message))

        try:
            # looping over the received messages and printing them.
            group.updateState(client_socket, user)

        except IOError as e:
            # handling the normal error on nonblocking connections.
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print(e)
                print(f'Reading error: {str(e)}')
                sys.exit()

            # If we did not receive anything, then continue.
            continue

        except Exception as e:
            print(f'Reading error: {str(e)}')
            print(e)
            sys.exit()

    mainMenu()


def logout():
    global user 
    print('Goodbye \n\n\n')

    # Close and shutdown socket
    global client_socket 
    client_socket.shutdown(socket.SHUT_RDWR)
    client_socket.close()

    # encrypt and remove raw file
    with open(f"{user.username}-data.pkl", "rb") as fIn:
        with open("data.txt.aes", "wb") as fOut:
            pyAesCrypt.encryptStream(fIn, fOut, password)

    remove(f"{user.username}-data.pkl")

    # Reset user 
    user = None

    print('Welcome to the secure discussion forum! Please create an account, or log in!')
    startupMenu()


def mainMenu():
    print('Main menu:')
    print('1. Open a groupchat \n2. Create groupchat \n3. View groupchat invitations \n4. Log out')
    choice = input("> ")

    if choice == '1':
        selectGroupchat()

    elif choice == '2':
        user.createGroup(client_socket)
        mainMenu()

    elif choice == '3':
        user.viewInvitations(client_socket)
        mainMenu()

    elif choice == '4':
        logout()

    else:
        print('Sorry, please choose a valid option')
        mainMenu(client_socket)


def startupMenu():
    print('1: Create an account \n2: Log in')
    choice = input('> ')

    if choice == '1':
        if createAccount():
            login()
        else:
            startupMenu()

    elif choice == '2': 
        login()


startupMenu()