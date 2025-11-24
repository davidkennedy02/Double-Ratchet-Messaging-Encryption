import socket
import select
import json
import db_model
import ssl
import bcrypt
import base64
import time
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

Session = sessionmaker(bind=db_model.engine)

# Retry logic for DB connection
max_retries = 10
retry_delay = 5
session = None

for i in range(max_retries):
    try:
        # Try to create tables to check connection
        db_model.Base.metadata.create_all(db_model.engine)
        session = Session()
        print("Connected to database successfully.")
        break
    except OperationalError as e:
        print(f"Database not ready yet, retrying in {retry_delay} seconds... ({i+1}/{max_retries})")
        time.sleep(retry_delay)
    except Exception as e:
        print(f"Unexpected error connecting to DB: {e}")
        time.sleep(retry_delay)

if not session:
    print("Could not connect to database after multiple retries.")
    exit(1)

# defining the header length.
HEADER_LENGTH = 10

# defining the IP address and Port Number.
IP = "0.0.0.0"
PORT = 5000

""" 
Creating a server socket and providing the address family (socket.AF_INET) and type of connection (socket.SOCK_STREAM), i.e. using TCP connection.
"""
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

"""
Modifying the socket to allow us to reuse the address. 
We have to provide the socket option level and set the REUSEADDR (as a socket option) to 1 so that address is reused.
"""
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Binding the socket with the IP address and Port Number.
server_socket.bind((IP, PORT))

# Making the server listen to new connections.
server_socket.listen()

# List of sockets for select.select()
sockets_list = [server_socket]

# A set to contain the connected clients in the form name : socketVar
clients = {}

print(f'Listening for connections on IP = {IP} at PORT = {PORT}')

# A function for handling the received message.
def receive_message(client_socket: socket.socket):
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
        return {'header': message_header, 'data': client_socket.recv(message_length)}

    except:
        return False

    
def createAccount(client_socket: socket.socket, userInfo):
    print('Received a request to create an account...')
    print('Hashing password...')
    password = bcrypt.hashpw(bytes(userInfo['password'], 'utf-8'), base64.decodebytes(userInfo['salt'].encode('utf-8')))

    salt = userInfo['salt']
    
    try:
        new_user = db_model.User(username=userInfo['username'], 
                                 password=password, 
                                 salt=salt,
                                 cert_tls=userInfo['certTLS'], 
                                 identity_key=userInfo['IK'], 
                                 signed_pre_key=userInfo['SPK'],
                                 signature=userInfo['SIG']
                                 )
        session.add(new_user)
        session.commit()
        print("User successfully added!")

        response = {
            'request': 'create_account',
            'result': 'success'
        }
        
    except Exception as e:
        session.rollback()
        print(e)
        print("User could not be added ")

        response = {
            'request': 'create_account',
            'result': 'failure'
        }

    finally:
        serialisedResponse = json.dumps(response).encode('utf-8')
        header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

        client_socket.send(header + serialisedResponse)
    

def login(client_socket: socket.socket, userInfo):
    """
    Need to remember to add connection to list of connections to monitor, as these connections will need constant updates with regards to 
    new messages. 
    """

    print('Received a request to log in...')
    try:
        existingUser = session.query(db_model.User).filter_by(username=userInfo['username']).first()
        assert(existingUser != None)
        password = bcrypt.hashpw(bytes(userInfo['password'], 'utf-8'), base64.decodebytes((existingUser.salt).encode('utf-8')))
        assert password == bytes(existingUser.password, 'utf-8')

        # Assigning username to their socket 
        clients[existingUser.username] = client_socket

        for k, v in clients.items():
            print (f"{k} : {v}")

        response = {
            'request': 'login',
            'result': 'success'
        }
        serialisedResponse = json.dumps(response).encode('utf-8')
        header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

        client_socket.send(header + serialisedResponse)
        
    except Exception as e:
        print(e)
        print("Credential match not found")

        response = {
            'request': 'login',
            'result': 'failure'
        }
        serialisedResponse = json.dumps(response).encode('utf-8')
        header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

        client_socket.send(header + serialisedResponse)
     

def createGroup(notified_socket: socket.socket, groupInfo):

    print('Received a request to create a group...')

    try:

        member1 = session.query(db_model.User).filter_by(username=groupInfo['creator']).first()
        member2 = session.query(db_model.User).filter_by(username=groupInfo['member']).first()
        assert((member1 != None) and (member2 != None))

        newGroup = db_model.Group(name=groupInfo['groupname'])
        newGroup.users.append(member1)
        newGroup.users.append(member2)

        session.add(newGroup)
        session.commit()
        
        print(f'Group {groupInfo["groupname"]} created!')

        response = {
            'request': 'create_group',
            'result': 'success',
            'FIK': member2.identity_key,
            'FSPK': member2.signed_pre_key,
            'FSIG': member2.signature
        }

        print('Payload created...')

        serialisedResponse = json.dumps(response).encode('utf-8')
        header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

        print('Message created...')

        notified_socket.send(header + serialisedResponse)

        print('Response sent!')
        
    except Exception as e:
        print(e)
        print("User was not found")

        response = {
            'request': 'create_group',
            'result': 'failure'
        }

        serialisedResponse = json.dumps(response).encode('utf-8')
        header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

        notified_socket.send(header + serialisedResponse)

        print('Failed response sent!')
    
    
def sendMessage(messageInfo):
    '''
    payload = {
                'request': 'send_message',
                'group': self.groupName,
                'sender': user.username,
                'addressee': member.username,
                'cipher': cipher,
                'FDH': encodeKey(member.DHratchet)
            }
    '''

    print('Received a request to send a message...')
    

    addressee = messageInfo['addressee']
    groupName = messageInfo['groupName']
    content = json.dumps(messageInfo)

    newMessage = db_model.Message(type='regular', group=groupName, address=addressee, content=content)

    session.add(newMessage)
    session.commit()
    

def sendInvitation(messageInfo):
    print('Received a request to send an invitation...')

    newInvite = db_model.Message(address=messageInfo['addressee'], 
                                 type='invitation', 
                                 group=messageInfo['content']['groupName'], 
                                 content=json.dumps(messageInfo['content']).encode('utf-8')
                                )

    session.add(newInvite)
    session.commit()


def provideInvitation(notified_socket: socket.socket, messageInfo):
    print('Received a request to provide an invitation...')

    invitation = session.query(db_model.Message).filter_by(address=messageInfo['user'], type='invitation').first()

    if invitation:
        invitationInfo = json.loads(invitation.content)
        response = {
            'result': 'success',
            'invitation': invitationInfo
        }

        session.delete(invitation)
        session.commit()

    else:
        response = {
            'result': 'failure'
        }

    serialisedResponse = json.dumps(response).encode('utf-8')
    header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

    notified_socket.send(header + serialisedResponse)


def provideMessage(notified_socket: socket.socket, messageInfo):
    '''
    payload = {
            'request': 'request_message',
            'group': self.groupName,
            'user': username
        }
    '''

    print('Received a request to provide a message...')

    groupName = messageInfo['group']
    addressee = messageInfo['user']

    # Get all messages that aren't invitations for groups 
    retrievedMessage = session.query(db_model.Message).filter_by(group=groupName, address=addressee).filter(db_model.Message.type != 'invitation').first()

    if retrievedMessage:

        # Construct response message 
        content = json.loads(retrievedMessage.content)

        response = {
            'result': 'success',
            'type': retrievedMessage.type,
            'content': content
        }

        # Respond to the user's request with the message content 
        serialisedResponse = json.dumps(response).encode('utf-8')
        header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

        notified_socket.send(header + serialisedResponse)

        # Remove message from database once sent - this should ideally be done after confirmation from the user that they received the message
        session.delete(retrievedMessage)
        session.commit()

    else:
        response = {
            'result': 'failure'
        }

        # Respond to the user's request with the message content 
        serialisedResponse = json.dumps(response).encode('utf-8')
        header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

        notified_socket.send(header + serialisedResponse)


def acceptInvitation(messageInfo):
    
    '''
    payload = {
            'request': 'send_DH',
            'sender': self.username,
            'receiver': initialMember.username,
            'groupName': groupName,
            'dh_pub': encodeKey(initialMember.DHratchet)
        }

    '''
    addressee = messageInfo['receiver']
    groupName = messageInfo['groupName']
    content = json.dumps(messageInfo)

    newMessage = db_model.Message(type='invitation_response', group=groupName, address=addressee, content=content)

    session.add(newMessage)
    session.commit()


def userDetails(notified_socket: socket.socket, messageInfo):

    '''
        payload = {
            'result': 'success',
            'FIK': FIK,
            'FSPK': FSPK,
            'FSIG': FSIG
        }
        '''

    # Find user in database
    user = session.query(db_model.User).filter_by(username=messageInfo['username']).first()

    # If user exists...
    if user:

        response = {
            'result': 'success',
            'FIK': user.identity_key,
            'FSPK': user.signed_pre_key,
            'FSIG': user.signature
        }

        # Respond to the user's request with the message content 
        serialisedResponse = json.dumps(response).encode('utf-8')
        header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

        notified_socket.send(header + serialisedResponse)

    else:

        response = {
            'result': 'failure',
        }

        # Respond to the user's request with the message content 
        serialisedResponse = json.dumps(response).encode('utf-8')
        header = f"{len(serialisedResponse):<{HEADER_LENGTH}}".encode('utf-8')

        notified_socket.send(header + serialisedResponse)



# running an infinite loop to accept continuous client requests.
while True:
    # Read the data using a select module from the socketLists.
    read_sockets, _, exception_sockets = select.select(
        sockets_list, [], sockets_list)

    # Iterating over the notified sockets.
    for notified_socket in read_sockets:
        """
        If the notified socket is a server socket then we have a new connection, so add it using the accept() method.
        """
        if notified_socket == server_socket:
            client_socket, client_address = server_socket.accept()

            # Initial one-way wrapping of socket for encryption, but not authentication
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile="servercert.pem", keyfile="serverkey.pem")
            client_socket = context.wrap_socket(client_socket, server_side=True)

            message = receive_message(client_socket)

            # If False - client disconnected before he sent his name
            if message is False:
                continue
            
            sockets_list.append(client_socket)

            print('Accepted new connection from {}:{}'.format(*client_address))

            messageInfo = json.loads(message['data'])

            if messageInfo['request'] == 'create_account':
                createAccount(client_socket, messageInfo)

            elif messageInfo['request'] == 'login':
                login(client_socket, messageInfo)

        
        # Else an existing socket is sending a message so handling the existing client.
        else:
            print('Received a message from a connected client...')
            # Receiving the message.
            message = receive_message(notified_socket)

            # If no message is accepted then finish the connection.
            if message is False:
                print('Closed connection')

                # Removing the socket from the list of the socket.socket()
                sockets_list.remove(notified_socket)
                
                # Remove client from list of clients 
                for k, v in clients.items():
                    if v == notified_socket:
                        target = k
                        continue

                # Silence possible errors about clients leaving twice 
                try:
                    clients.pop(target, _)

                except Exception as e:
                    pass

                continue

            messageInfo = json.loads(message['data'])

            if messageInfo['request'] == 'login':
                login(notified_socket, messageInfo)

            elif messageInfo['request'] == 'create_group':
                createGroup(notified_socket, messageInfo)
            
            elif messageInfo['request'] == 'send_message':
                sendMessage(messageInfo)

            elif messageInfo['request'] == 'request_message':
                provideMessage(notified_socket, messageInfo)

            elif messageInfo['request'] == 'invitation':
                sendInvitation(messageInfo)

            elif messageInfo['request'] == 'request_invitations':
                provideInvitation(notified_socket, messageInfo)

            elif messageInfo['request'] == 'accept_invitation':
                acceptInvitation(messageInfo)

            elif messageInfo['request'] == 'user_details':
                userDetails(notified_socket, messageInfo)
