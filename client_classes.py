import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
import xeddsa
import json
import sys
import errno
import pickle
 
# defining the header length.
HEADER_LENGTH = 10


def sendMessage(client_socket, payload):
    serialPayload = json.dumps(payload).encode('utf-8')
    header = f"{len(serialPayload):<{HEADER_LENGTH}}".encode('utf-8')

    client_socket.send(header + serialPayload)


def receive_message(client_socket):
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


def hkdf(input, length):
    hkdf = HKDF(algorithm = hashes.SHA256(), length=length, salt=b'', info=b'', backend = default_backend())
    return hkdf.derive(input)


def pad(msg):
    num = 16 - (len(msg) % 16)
    return bytes(msg, 'utf-8') + bytes([num] * num)


def unpad(msg):
    return str(msg[:-msg[-1]], 'utf-8')


def encodeKey(key):
    return base64.encodebytes(key.public_key().public_bytes_raw()).decode('utf-8')


def decodeKey(key):
    return X25519PublicKey.from_public_bytes(base64.decodebytes(key.encode('utf-8')))


def encodeSig(sig):
    return base64.encodebytes(sig).decode('utf-8')


def decodeSig(sig):
    return base64.decodebytes(sig.encode('utf-8'))


def encodeCipher(cipher):
    return base64.encodebytes(cipher).decode('utf-8')


def decodeCipher(cipher):
    return base64.decodebytes(cipher.encode('utf-8'))


class Member(object):
    """
    Note: user will need to be a member in each of their groupchats 
    """
    def __init__(self, username, sharedKey) -> None:
        self.username = username
        self.sharedKey = sharedKey

        self.DHratchet = X25519PrivateKey.generate()
        self.root_ratchet = None
        self.send_ratchet = None 
        self.recv_ratchet = None 
        self.FDH = None
        self.init_ratchets()


    def setFDH(self, FDH):
        self.FDH = FDH


    def init_ratchets(self):
        # initialise the root chain with the shared key
        self.root_ratchet = SymRatchet(self.sharedKey)
        # initialise the sending and recving chains
        self.recv_ratchet = SymRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymRatchet(self.root_ratchet.next()[0])


    def dh_ratchet_send(self, FDH):
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(FDH)
        shared_send = self.root_ratchet.next(dh_send)[0]

        self.send_ratchet = SymRatchet(shared_send)


    def dh_ratchet_receive(self, FDH):
        dh_recv = self.DHratchet.exchange(FDH)
        shared_rcv = self.root_ratchet.next(dh_recv)[0]
        
        self.recv_ratchet = SymRatchet(shared_rcv)


    def encrypt(self, msg):
        self.dh_ratchet_send(self.FDH)
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))

        return cipher 
    

    def decrypt(self, cipher):
        self.dh_ratchet_receive(self.FDH)
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))

        return msg
    

# This will need to be initialised for each user in the group to each other user 
class SymRatchet(object):
    def __init__(self, sharedKey) -> None:
        self.state = sharedKey

    def next(self, inp=b''):
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv


class User(object):
    def __init__(self, username: str, IK : X25519PrivateKey, SPK: X25519PrivateKey, SIG: bytes) -> None:
        self.username = username
        self.IK = IK
        self.SPK = SPK
        self.SIG = SIG
        self.EK = None
        self.groups = []
    

    def joinGroup(self, client_socket, invitation):

        groupName = invitation['groupName']
        sender = invitation['creator']

        # Create public keys from bytes 
        FIK = decodeKey(invitation['FIK'])
        FEK = decodeKey(invitation['FEK'])
        FDH = decodeKey(invitation['FDH'])

        # Calculate shared key 
        sharedKey = self.x3dhReceived(FIK=FIK, FEK=FEK)

        # Create member for group 
        initialMember = Member(username=sender, sharedKey=sharedKey)
        initialMember.setFDH(FDH)

        existingGroup = None
        for group in self.groups:
            if group.groupName == groupName:
                existingGroup = group

        if existingGroup:
            group.members.append(initialMember)

        else:

            # Create group with initial member 
            newGroup = Group(groupName=groupName, initialMember=initialMember)

            # Add group to list of groups 
            self.groups.append(newGroup)

        # Send confirmation of join along with DH public key to allow message sending 
        payload = {
            'request': 'accept_invitation',
            'sender': self.username,
            'receiver': initialMember.username,
            'groupName': groupName,
            'dh_pub': encodeKey(initialMember.DHratchet)
        }

        sendMessage(client_socket, payload)

        self.saveData()


    def createGroup(self, client_socket):

        # Enter name and initial member 
        groupName = input("What's the name of your group? \n> ")

        member = input("Who's the initial member of your group? \n> ")

        print("Ok! Sending information to the server...")

        # Send to server 

        groupInfo = {
        'request': 'create_group',
        'groupname': groupName,
        'creator': self.username, 
        'member': member, 
        }

        sendMessage(client_socket, groupInfo)

        creationSuccess = False 

        response = False 
        while not response:
            try:
                # Decoding the received response 
                message = receive_message(client_socket)
                if not message:
                    continue

                response = True

                messageInfo = message['data']
                
                if messageInfo['result'] == 'success':
                    
                    creationSuccess = True
                    print('Successfully created the groupchat!')
                
                else:
                    print('Creation of groupchat failed...')

            except IOError as e:
                # handling the normal error on nonblocking connections.
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print(e)
                    print('Reading error: {}'.format(str(e)))
                    sys.exit()

                # If we did not receive anything, then continue.
                continue

        # If positive response: 
        if creationSuccess:

            # Convert received keys from server to valid version 
            FIK = decodeKey(messageInfo['FIK'])
            FSPK = decodeKey(messageInfo['FSPK'])
            FSIG = decodeSig(messageInfo['FSIG'])

            # Say this will pass for now because signature should always be correct
            sharedKey = self.x3dhSend(FIK=FIK, FSPK=FSPK, FSIG=FSIG)

            # Create member 
            initialMember = Member(username=member, sharedKey=sharedKey)

            '''
            This should include initialising ratchets and DH ratchet keys 
            '''

            # Create the group locally with self in it and add it to the user's list of groups 
            newGroup = Group(groupName=groupName, initialMember=initialMember)
            self.groups.append(newGroup)

            # Send the server own information for new member 
            groupInfo = {
                'request': 'invitation',
                'addressee': member,
                'content': {
                    'groupName': groupName,
                    'creator' :self.username,
                    'FIK': encodeKey(self.IK),
                    'FSPK': encodeKey(self.SPK),
                    'FEK': encodeKey(self.EK),
                    'FDH': encodeKey(initialMember.DHratchet)
                }
            }

            # Send the server the invitation to send to the new member 
            sendMessage(client_socket, groupInfo)

        self.saveData()


    def viewInvitations(self, client_socket):
        # groupInfo = {
        #         'request': 'invitation',
        #         'addressee': member,
        #         'content': {
        #             'groupName': groupName,
        #             'creator' :self.username,
        #             'FIK': encodeKey(self.IK),
        #             'FSPK': encodeKey(self.SPK),
        #             'FEK': encodeKey(self.EK),
        #             'FDH': encodeKey(initialMember.DHratchet)
        #         }
        #     }
        payload = {
            'request': 'request_invitations',
            'user': self.username
        }

        sendMessage(client_socket, payload)

        response = False 
        invitation = False 
        while not response:
            try:
                # Decoding the received response 
                message = receive_message(client_socket)
                if not message:
                    continue

                response = True

                messageInfo = message['data']

                print(messageInfo)
                
                if messageInfo['result'] == 'success':
                    
                    invitation = True
                    print('You have an invitation!')
                
                else:
                    print('You have no invitations')

            except IOError as e:
                # handling the normal error on nonblocking connections.
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print(e)
                    print('Reading error: {}'.format(str(e)))
                    sys.exit()

                # If we did not receive anything, then continue.
                continue
        
        if invitation:
            print(f'Invitation to join group {messageInfo["invitation"]["groupName"]} from {messageInfo["invitation"]["creator"]}. ')

            choice = input("Would you like to join this group? (y/n) \n> ")

            if choice == 'y':
                self.joinGroup(client_socket, messageInfo['invitation'])
            else: 
                print('You have ignored this invitation...')


    def x3dhReceived(self, FIK, FEK):
        dh1 = self.SPK.exchange(FIK)
        dh2 = self.IK.exchange(FEK)
        dh3 = self.SPK.exchange(FEK)

        sharedKey = hkdf(dh1 + dh2 + dh3, 32)

        return sharedKey


    def verifySignature(self, FIK, FSPK, FSIG):
        FIKED = xeddsa.bindings.curve25519_pub_to_ed25519_pub(curve25519_pub=FIK.public_bytes_raw(), set_sign_bit=False)
        FIKEDSIGN = xeddsa.bindings.curve25519_pub_to_ed25519_pub(curve25519_pub=FIK.public_bytes_raw(), set_sign_bit=True)
        try:
            assert (
                xeddsa.bindings.ed25519_verify(sig=FSIG, ed25519_pub=FIKED, msg=FSPK.public_bytes_raw()) or 
                xeddsa.bindings.ed25519_verify(sig=FSIG, ed25519_pub=FIKEDSIGN, msg=FSPK.public_bytes_raw()))
            print("The signature is valid")
            return True
        except:
            print("Invalid signature!")
            return True


    def x3dhSend(self, FIK, FSPK, FSIG):
        
        assert self.verifySignature(FIK, FSPK, FSIG)

        self.generateEK()
        dh1 = self.IK.exchange(FSPK)
        dh2 = self.EK.exchange(FIK)
        dh3 = self.EK.exchange(FSPK)

        sharedKey = hkdf(dh1 + dh2 + dh3, 32)

        return sharedKey


    def generateEK(self):
        self.EK = X25519PrivateKey.generate()


    def saveData(self):
        self.IK = self.IK.private_bytes_raw()
        self.SPK = self.SPK.private_bytes_raw()
        
        if self.EK:
            self.EK = self.EK.private_bytes_raw()

        # If user has groups, encode each member's information   
        if len(self.groups) > 0:
            for group in self.groups:
                for member in group.members:

                    # Convert each key to bytes appropriately 
                    member.DHratchet = member.DHratchet.private_bytes_raw()

                    if member.FDH:
                        member.FDH = member.FDH.public_bytes_raw()

        with open(f'{self.username}-data.pkl', 'wb') as file:
            pickle.dump(self, file)

        # print('User data saved')

        self.loadKeys()


    def loadKeys(self):
        self.IK = X25519PrivateKey.from_private_bytes(self.IK)
        self.SPK = X25519PrivateKey.from_private_bytes(self.SPK)

        if self.EK:
            self.EK = X25519PrivateKey.from_private_bytes(self.EK)


        if len(self.groups) > 0:
            for group in self.groups:
                for member in group.members:

                    # Convert bytes to key appropriately 
                    member.DHratchet = X25519PrivateKey.from_private_bytes(member.DHratchet)

                    if member.FDH:
                        member.FDH = X25519PublicKey.from_public_bytes(member.FDH)

        # print("Keys loaded")


class Group(object):
    def __init__(self, groupName, initialMember: Member) -> None:

        self.groupName = groupName
        self.messages = []
        self.members = [initialMember]


    def sendMessage(self, user: User, client_socket, msg):

        # for each user in the group:
        for member in self.members:
            if member.FDH:
                cipher = member.encrypt(msg)

                # send message with additional information

                payload = {
                    'request': 'send_message',
                    'groupName': self.groupName,
                    'sender': user.username,
                    'addressee': member.username,
                    'cipher': encodeCipher(cipher),
                    'FDH': encodeKey(member.DHratchet)
                }

                sendMessage(client_socket, payload)


    def receiveMessage(self, msg):
        # payload = {
        #         'request': 'send_message',
        #         'group': self.groupName,
        #         'sender': user.username,
        #         'addressee': member.username,
        #         'cipher': cipher, 
        #         'FDH': new FDH
        #     }

        # find who sent the message 
        sender = None

        for member in self.members:
            if member.username == msg['sender']:
                sender = member 

        # use their Diffie Hellman key they sent with the message
        FDH = decodeKey(msg['FDH'])
        sender.setFDH(FDH)

        # decrypt the message using the appropriate keys 
        message = sender.decrypt(decodeCipher(msg['cipher']))

        # Save the message to the user data 
        self.messages.append((sender.username, message))

        # Print the message
        print(f"{sender.username} > {message}")

    
    def confirmMemberFDH(self, messageInfo):
        # payload = {
        #     'request': 'send_DH',
        #     'sender': self.username,
        #     'receiver': initialMember.username,
        #     'groupName': groupName,
        #     'dh_pub': encodeKey(initialMember.DHratchet)
        # }

        sender = None 
        for member in self.members:
            if member.username == messageInfo['sender']:
                sender = member 
        
        FDH = decodeKey(messageInfo['dh_pub'])

        sender.setFDH(FDH)


    def addMember(self, user: User, username, client_socket):

        '''
        payload = {
            'result': 'success',
            'FIK': FIK,
            'FSPK': FSPK,
            'FSIG': FSIG
        }
        '''

        request = {
        'request': 'user_details',
        'username': username, 
        }

        sendMessage(client_socket, request)

        retrievalSuccess = False 

        response = False 
        while not response:
            try:
                # Decoding the received response 
                message = receive_message(client_socket)
                if not message:
                    continue

                response = True

                messageInfo = message['data']
                
                if messageInfo['result'] == 'success':
                    
                    retrievalSuccess = True
                    print('Successfully retrieved user details...')
                
                else:
                    print('User was not found...')

            except IOError as e:
                # handling the normal error on nonblocking connections.
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print(e)
                    print('Reading error: {}'.format(str(e)))
                    sys.exit()

                # If we did not receive anything, then continue.
                continue

        # If positive response: 
        if retrievalSuccess:

            # Convert received keys from server to valid version 
            FIK = decodeKey(messageInfo['FIK'])
            FSPK = decodeKey(messageInfo['FSPK'])
            FSIG = decodeSig(messageInfo['FSIG'])

            # Say this will pass for now because signature should always be correct
            sharedKey = user.x3dhSend(FIK=FIK, FSPK=FSPK, FSIG=FSIG)

            # Create member 
            newMember = Member(username=username, sharedKey=sharedKey)

            # Create the group locally with self in it and add it to the user's list of groups 
            self.members.append(newMember)

            # Send the server own information for new member 
            groupInfo = {
                'request': 'invitation',
                'addressee': username,
                'content': {
                    'groupName': self.groupName,
                    'creator' :user.username,
                    'FIK': encodeKey(user.IK),
                    'FSPK': encodeKey(user.SPK),
                    'FEK': encodeKey(user.EK),
                    'FDH': encodeKey(newMember.DHratchet)
                }
            }

            # Send the server the invitation to send to the new member 
            sendMessage(client_socket, groupInfo)

        user.saveData()


    def removeMember(self, username):

        # Delete member from list of members 

        pass


    def updateState(self, client_socket, user: User):

        '''
        response = {
        'result': 'success',
        'type': type,
        'content': content
        }
        '''

        payload = {
            'request': 'request_message',
            'group': self.groupName,
            'user': user.username
        }

        sendMessage(client_socket, payload)

        response = False 
        recvMessage = False
        while not response:
            try:
                # Decoding the received response 
                message = receive_message(client_socket)
                if not message:
                    continue

                response = True

                messageInfo = message['data']
                
                if messageInfo['result'] == 'success':
                    recvMessage = True

                else:
                    user.saveData()


            except IOError as e:
                # handling the normal error on nonblocking connections.
                if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                    print(e)
                    print('Reading error: {}'.format(str(e)))
                    sys.exit()

                # If we did not receive anything, then continue.
                continue

        # We haven't had a response from the server saying no more messages yet
        if recvMessage:

            if messageInfo['type'] == 'regular':
                self.receiveMessage(messageInfo['content'])
            
            elif messageInfo['type'] == 'invitation_response':
                self.confirmMemberFDH(messageInfo['content'])
            
            self.updateState(client_socket, user)

