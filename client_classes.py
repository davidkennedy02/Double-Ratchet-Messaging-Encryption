import base64
import json
import pickle
import nacl.signing
import nacl.public
from nacl.public import PrivateKey, PublicKey, Box
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

# defining the header length.
HEADER_LENGTH = 10

def sendMessage(client_socket, payload):
    serialPayload = json.dumps(payload).encode('utf-8')
    header = f"{len(serialPayload):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(header + serialPayload)

def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode('utf-8').strip())
        return {'header': message_header, 'data': json.loads(client_socket.recv(message_length).decode('utf-8'))}
    except:
        return False

def hkdf(input_key, length):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'', info=b'', backend=default_backend())
    return hkdf.derive(input_key)

def pad(msg):
    num = 16 - (len(msg) % 16)
    return bytes(msg, 'utf-8') + bytes([num] * num)

def unpad(msg):
    return str(msg[:-msg[-1]], 'utf-8')

def encodeKey(key):
    # Key is bytes
    return base64.encodebytes(key).decode('utf-8')

def decodeKey(key_str):
    return base64.decodebytes(key_str.encode('utf-8'))

def encodeSig(sig):
    return base64.encodebytes(sig).decode('utf-8')

def decodeSig(sig):
    return base64.decodebytes(sig.encode('utf-8'))

def encodeCipher(cipher):
    return base64.encodebytes(cipher).decode('utf-8')

def decodeCipher(cipher):
    return base64.decodebytes(cipher.encode('utf-8'))

class Member(object):
    def __init__(self, username, sharedKey, is_initiator=False) -> None:
        self.username = username
        self.sharedKey = sharedKey
        
        # DH Ratchet Key (Curve25519)
        self.DHratchet = PrivateKey.generate()
        self.root_ratchet = None
        self.send_ratchet = None 
        self.recv_ratchet = None 
        self.FDH = None # Foreign DH Key (PublicKey)
        self.init_ratchets(is_initiator)

    def setFDH(self, FDH_bytes):
        self.FDH = PublicKey(FDH_bytes)

    def init_ratchets(self, is_initiator):
        self.root_ratchet = SymRatchet(self.sharedKey)
        if is_initiator:
            # Initiator: Send then Recv
            self.send_ratchet = SymRatchet(self.root_ratchet.next()[0])
            self.recv_ratchet = SymRatchet(self.root_ratchet.next()[0])
        else:
            # Responder: Recv then Send
            self.recv_ratchet = SymRatchet(self.root_ratchet.next()[0])
            self.send_ratchet = SymRatchet(self.root_ratchet.next()[0])

    def dh_ratchet_send(self, FDH):
        self.DHratchet = PrivateKey.generate()
        # Perform DH exchange
        dh_send = Box(self.DHratchet, FDH).shared_key()
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymRatchet(shared_send)

    def dh_ratchet_receive(self, FDH):
        dh_recv = Box(self.DHratchet, FDH).shared_key()
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

class SymRatchet(object):
    def __init__(self, sharedKey) -> None:
        self.state = sharedKey

    def next(self, inp=b''):
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv

class User(object):
    def __init__(self, username: str, IK, SPK, SIG: bytes) -> None:
        self.username = username
        self.IK = IK # SigningKey (Ed25519)
        self.SPK = SPK # PrivateKey (Curve25519)
        self.SIG = SIG # Signature of SPK public key by IK
        self.EK = None # Ephemeral Key (PrivateKey)
        self.groups = []
    
    def joinGroup(self, client_socket, invitation):
        groupName = invitation['groupName']
        sender = invitation['creator']

        # Decode keys (bytes)
        FIK_bytes = decodeKey(invitation['FIK']) # Ed25519 Public
        FEK_bytes = decodeKey(invitation['FEK']) # Curve25519 Public
        FDH_bytes = decodeKey(invitation['FDH']) # Curve25519 Public
        
        sharedKey = self.x3dhReceived(FIK_bytes, FEK_bytes)

        initialMember = Member(username=sender, sharedKey=sharedKey, is_initiator=False)
        initialMember.setFDH(FDH_bytes)

        existingGroup = None
        for group in self.groups:
            if group.groupName == groupName:
                existingGroup = group

        if existingGroup:
            # Check if member already exists?
            pass
        else:
            newGroup = Group(groupName=groupName, initialMember=initialMember)
            self.groups.append(newGroup)

        # Send confirmation
        payload = {
            'request': 'accept_invitation',
            'sender': self.username,
            'receiver': initialMember.username,
            'groupName': groupName,
            'dh_pub': encodeKey(bytes(initialMember.DHratchet.public_key))
        }
        sendMessage(client_socket, payload)
        self.saveData()

    def x3dhReceived(self, FIK_bytes, FEK_bytes):
        # FIK is Ed25519 Public. Convert to Curve25519 for DH.
        fik_verify = nacl.signing.VerifyKey(FIK_bytes)
        fik_curve = fik_verify.to_curve25519_public_key()
        
        fek_curve = PublicKey(FEK_bytes)

        # DH1 = SPK (Mine) + FIK (Theirs)
        dh1 = Box(self.SPK, fik_curve).shared_key()
        
        # DH2 = IK (Mine, converted) + FEK (Theirs)
        ik_curve = self.IK.to_curve25519_private_key()
        dh2 = Box(ik_curve, fek_curve).shared_key()
        
        # DH3 = SPK (Mine) + FEK (Theirs)
        dh3 = Box(self.SPK, fek_curve).shared_key()

        sharedKey = hkdf(dh1 + dh2 + dh3, 32)
        return sharedKey

    def x3dhSend(self, FIK_bytes, FSPK_bytes, FSIG_bytes):
        # Verify signature of FSPK with FIK
        fik_verify = nacl.signing.VerifyKey(FIK_bytes)
        try:
            fik_verify.verify(FSPK_bytes, FSIG_bytes)
            print("Signature valid")
        except:
            print("Invalid signature!")
        
        fik_curve = fik_verify.to_curve25519_public_key()
        fspk_curve = PublicKey(FSPK_bytes)

        self.generateEK()
        
        # DH1 = IK (Mine, converted) + FSPK (Theirs)
        ik_curve = self.IK.to_curve25519_private_key()
        dh1 = Box(ik_curve, fspk_curve).shared_key()
        
        # DH2 = EK (Mine) + FIK (Theirs)
        dh2 = Box(self.EK, fik_curve).shared_key()
        
        # DH3 = EK (Mine) + FSPK (Theirs)
        dh3 = Box(self.EK, fspk_curve).shared_key()

        sharedKey = hkdf(dh1 + dh2 + dh3, 32)
        return sharedKey

    def generateEK(self):
        self.EK = PrivateKey.generate()

    def saveData(self):
        # Convert keys to bytes for storage
        ik_bytes = bytes(self.IK)
        spk_bytes = bytes(self.SPK)
        ek_bytes = bytes(self.EK) if self.EK else None
        
        # Store members keys
        members_data = []
        for group in self.groups:
            g_data = {'name': group.groupName, 'members': [], 'messages': group.messages}
            for member in group.members:
                m_data = {
                    'username': member.username,
                    'sharedKey': member.sharedKey,
                    'DHratchet': bytes(member.DHratchet),
                    'FDH': bytes(member.FDH) if member.FDH else None,
                    'root_state': member.root_ratchet.state,
                    'send_state': member.send_ratchet.state,
                    'recv_state': member.recv_ratchet.state
                }
                g_data['members'].append(m_data)
            members_data.append(g_data)

        data = {
            'username': self.username,
            'IK': ik_bytes,
            'SPK': spk_bytes,
            'SIG': self.SIG,
            'EK': ek_bytes,
            'groups': members_data
        }

        with open(f'{self.username}-data.pkl', 'wb') as file:
            pickle.dump(data, file)

    def loadKeys(self):
        pass

class Group(object):
    def __init__(self, groupName, initialMember: Member) -> None:
        self.groupName = groupName
        self.messages = []
        self.members = [initialMember]

    def sendMessage(self, user: User, client_socket, msg):
        for member in self.members:
            if member.FDH:
                cipher = member.encrypt(msg)
                payload = {
                    'request': 'send_message',
                    'groupName': self.groupName,
                    'sender': user.username,
                    'addressee': member.username,
                    'cipher': encodeCipher(cipher),
                    'FDH': encodeKey(bytes(member.DHratchet.public_key))
                }
                sendMessage(client_socket, payload)

    def receiveMessage(self, msg):
        sender = None
        for member in self.members:
            if member.username == msg['sender']:
                sender = member 
        
        if sender:
            FDH = decodeKey(msg['FDH'])
            sender.setFDH(FDH)
            message = sender.decrypt(decodeCipher(msg['cipher']))
            self.messages.append((sender.username, message))

    def confirmMemberFDH(self, messageInfo):
        sender = None 
        for member in self.members:
            if member.username == messageInfo['sender']:
                sender = member 
        
        if sender:
            FDH = decodeKey(messageInfo['dh_pub'])
            sender.setFDH(FDH)

    def updateState(self, client_socket, user: User):
        payload = {
            'request': 'request_message',
            'group': self.groupName,
            'user': user.username
        }
        sendMessage(client_socket, payload)
        response = receive_message(client_socket)
        if response and response['data']['result'] == 'success':
            msg = response['data']
            if msg['type'] == 'regular':
                self.receiveMessage(msg['content'])
            elif msg['type'] == 'invitation_response':
                self.confirmMemberFDH(msg['content'])
