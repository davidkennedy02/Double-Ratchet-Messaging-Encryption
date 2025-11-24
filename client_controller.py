import socket
import ssl
import json
import pickle
import bcrypt
import errno
import os
from os import remove
import pyAesCrypt
import nacl.signing
import nacl.public
from client_classes import User, Group, encodeKey, encodeSig, decodeKey, decodeSig, Member
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime

HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 5000

class ClientController:
    def __init__(self):
        self.user = None
        self.client_socket = None
        self.password = None
        self.username = None

    def connect_one_way(self):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.create_default_context(cafile="servercert.pem")
            # Allow self-signed certs or IP mismatch if needed for dev
            context.check_hostname = False 
            context.verify_mode = ssl.CERT_REQUIRED
            
            client_socket = context.wrap_socket(client_socket, server_hostname=IP)
            client_socket.connect((IP, PORT))
            client_socket.setblocking(False)
            self.client_socket = client_socket
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def send_message(self, payload):
        if not self.client_socket:
            return False
        try:
            serialPayload = json.dumps(payload).encode('utf-8')
            header = f"{len(serialPayload):<{HEADER_LENGTH}}".encode('utf-8')
            self.client_socket.send(header + serialPayload)
            return True
        except Exception as e:
            print(f"Send error: {e}")
            return False

    def receive_message(self):
        if not self.client_socket:
            return False
        try:
            message_header = self.client_socket.recv(HEADER_LENGTH)
            if not len(message_header):
                return False
            message_length = int(message_header.decode('utf-8').strip())
            data = self.client_socket.recv(message_length).decode('utf-8')
            return {'header': message_header, 'data': json.loads(data)}
        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                pass
            return False
        except Exception as e:
            print(f'Reading error: {str(e)}')
            return False

    def login(self, username, password):
        self.username = username
        self.password = password
        
        try:
            with open(f'{username}-salt', 'rb') as file:
                salt = file.read()
        except FileNotFoundError:
            return False, "User not found locally (salt missing)."

        userInfo = {
            'request': 'login',
            'username': username,
            'password': password,
        }

        if not self.connect_one_way():
            return False, "Could not connect to server."

        self.send_message(userInfo)

        import time
        start_time = time.time()
        while time.time() - start_time < 10: 
            response = self.receive_message()
            if response:
                if response['data']['result'] == 'success':
                    if self.load_user_data(username, password):
                        return True, "Login successful."
                    else:
                        return False, "Failed to load local user data."
                else:
                    return False, "Login failed on server."
            time.sleep(0.1)
        
        return False, "Server timeout."

    def load_user_data(self, username, password):
        try:
            if os.path.exists(f"{username}-data.pkl.aes"):
                with open(f"{username}-data.pkl.aes", "rb") as fIn:
                    with open(f"{username}-data.pkl", "wb") as fOut:
                        # Derive key from password and salt for local decryption
                        with open(f'{username}-salt', 'rb') as file:
                            salt = file.read()
                        # Use bcrypt to derive a key/hash from password + salt
                        # We use the hash string as the password for pyAesCrypt
                        local_key = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
                        pyAesCrypt.decryptStream(fIn, fOut, local_key)
            
            with open(f"{username}-data.pkl", "rb") as file:
                data = pickle.load(file)
            
            # Reconstruct User object from dict
            ik = nacl.signing.SigningKey(data['IK'])
            spk = nacl.public.PrivateKey(data['SPK'])
            sig = data['SIG']
            
            self.user = User(username=username, IK=ik, SPK=spk, SIG=sig)
            if data['EK']:
                self.user.EK = nacl.public.PrivateKey(data['EK'])
            
            for g_data in data['groups']:
                # Reconstruct Group and Members
                # Need to handle initial member logic or just reconstruct list
                # Group constructor takes initialMember, but we have a list of members.
                # We can cheat and create empty group then add members.
                # But Group init requires initialMember.
                
                # Let's just pick the first member as initial?
                # Or modify Group class.
                # For now, hack:
                first_m_data = g_data['members'][0]
                first_m = self._reconstruct_member(first_m_data)
                
                group = Group(g_data['name'], first_m)
                group.messages = g_data.get('messages', [])
                group.members = [] # Clear and re-add all
                for m_data in g_data['members']:
                    group.members.append(self._reconstruct_member(m_data))
                
                self.user.groups.append(group)

            return True
        except Exception as e:
            print(f"Error loading data: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _reconstruct_member(self, m_data):
        m = Member(m_data['username'], m_data['sharedKey'], is_initiator=False)
        m.DHratchet = nacl.public.PrivateKey(m_data['DHratchet'])
        if m_data['FDH']:
            m.FDH = nacl.public.PublicKey(m_data['FDH'])
        
        # Restore ratchet states
        m.root_ratchet.state = m_data['root_state']
        m.send_ratchet.state = m_data['send_state']
        m.recv_ratchet.state = m_data['recv_state']
        return m

    def register(self, username, password):
        try:
            salt = bcrypt.gensalt(12, b"2b")
            with open(f'{username}-salt', 'wb') as file:
                file.write(salt)
            
            # Generate keys using PyNaCl
            # Identity Key (Ed25519 Signing Key)
            IK = nacl.signing.SigningKey.generate()
            
            # Signed Pre Key (Curve25519 Private Key)
            SPK = nacl.public.PrivateKey.generate()
            
            # Sign the SPK public key with IK
            SIG = IK.sign(bytes(SPK.public_key)).signature

            # Generate a self-signed certificate
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
                x509.NameAttribute(NameOID.COMMON_NAME, username),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            ).sign(key, hashes.SHA256())
            
            certTLS = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

            userInfo = {
                'request' : 'create_account',
                'username' : username, 
                'password' : password, 
                'salt': encodeSig(salt),
                'certTLS' : certTLS,
                'IK' : encodeKey(bytes(IK.verify_key)), # Send Public Verify Key
                'SPK': encodeKey(bytes(SPK.public_key)), # Send Public Curve Key
                'SIG': encodeSig(SIG)
            }

            if not self.connect_one_way():
                return False, "Could not connect to server."

            self.send_message(userInfo)

            import time
            start_time = time.time()
            while time.time() - start_time < 30: 
                response = self.receive_message()
                if response:
                    if response['data']['result'] == 'success':
                        self.user = User(username=username, IK=IK, SPK=SPK, SIG=SIG)
                        self.user.saveData()
                        
                        # Encrypt
                        with open(f"{username}-data.pkl", "rb") as fIn:
                            with open(f"{username}-data.pkl.aes", "wb") as fOut:
                                # Derive key from password and salt for local encryption
                                local_key = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
                                pyAesCrypt.encryptStream(fIn, fOut, local_key)
                        remove(f"{username}-data.pkl")
                        return True, "Account created."
                    else:
                        return False, "Server rejected creation."
                time.sleep(0.1)
            return False, "Timeout."

        except Exception as e:
            import traceback
            traceback.print_exc()
            return False, str(e)

    def get_groups(self):
        if self.user:
            return [g.groupName for g in self.user.groups]
        return []

    def get_messages(self, group_name):
        if self.user:
            for group in self.user.groups:
                if group.groupName == group_name:
                    return group.messages
        return []

    def send_group_message(self, group_name, message_text):
        if not self.user or not self.client_socket:
            return False
        
        for group in self.user.groups:
            if group.groupName == group_name:
                group.sendMessage(self.user, self.client_socket, message_text)
                group.messages.append((self.user.username, message_text))
                return True
        return False

    def check_for_updates(self):
        if not self.client_socket or not self.user:
            return

        try:
            for group in self.user.groups:
                # updateState checks for messages and appends them to group.messages
                # It returns True if a message was received, or we can check length change.
                # Let's modify updateState to return the message or just check the list.
                old_len = len(group.messages)
                group.updateState(self.client_socket, self.user)
                new_len = len(group.messages)
                if new_len > old_len:
                    pass # Messages are handled by UI refresh
        except Exception as e:
            print(f"Update error: {e}")

    def create_group(self, group_name, initial_member):
        if not self.user: return False, "Not logged in"
        
        groupInfo = {
            'request': 'create_group',
            'groupname': group_name,
            'creator': self.user.username, 
            'member': initial_member, 
        }
        self.send_message(groupInfo)
        
        import time
        start_time = time.time()
        while time.time() - start_time < 10:
            response = self.receive_message()
            if response:
                msg = response['data']
                if msg.get('request') == 'create_group' and msg.get('result') == 'success':
                     
                     FIK = decodeKey(msg['FIK'])
                     FSPK = decodeKey(msg['FSPK'])
                     FSIG = decodeSig(msg['FSIG'])
                     
                     sharedKey = self.user.x3dhSend(FIK, FSPK, FSIG)
                     
                     initialMember = Member(username=initial_member, sharedKey=sharedKey, is_initiator=True)
                     
                     newGroup = Group(groupName=group_name, initialMember=initialMember)
                     self.user.groups.append(newGroup)
                     
                     inviteInfo = {
                        'request': 'invitation',
                        'addressee': initial_member,
                        'content': {
                            'groupName': group_name,
                            'creator' :self.user.username,
                            'FIK': encodeKey(bytes(self.user.IK.verify_key)),
                            'FSPK': encodeKey(bytes(self.user.SPK.public_key)),
                            'FEK': encodeKey(bytes(self.user.EK.public_key)),
                            'FDH': encodeKey(bytes(initialMember.DHratchet.public_key))
                        }
                    }
                     self.send_message(inviteInfo)
                     self.user.saveData()
                     return True, "Group created"
                elif msg.get('request') == 'create_group':
                    return False, "Group creation failed"
            time.sleep(0.1)
        return False, "Timeout"

    def check_invitations(self):
        if not self.user: return []
        
        payload = {
            'request': 'request_invitations',
            'user': self.user.username
        }
        self.send_message(payload)
        
        import time
        start_time = time.time()
        invites = []
        while time.time() - start_time < 5:
            response = self.receive_message()
            if response:
                msg = response['data']
                if msg.get('result') == 'success':
                    invites.append(msg['invitation'])
                    return invites
                else:
                    return []
            time.sleep(0.1)
        return []

    def accept_invitation(self, invitation):
        if not self.user: return False
        try:
            self.user.joinGroup(self.client_socket, invitation)
            return True
        except Exception as e:
            print(f"Accept invite error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def logout(self):
        if self.user and self.password:
            try:
                self.user.saveData()
                with open(f"{self.user.username}-data.pkl", "rb") as fIn:
                    with open(f"{self.user.username}-data.pkl.aes", "wb") as fOut:
                        # Derive key from password and salt for local encryption
                        with open(f'{self.user.username}-salt', 'rb') as file:
                            salt = file.read()
                        local_key = bcrypt.hashpw(self.password.encode('utf-8'), salt).decode('utf-8')
                        pyAesCrypt.encryptStream(fIn, fOut, local_key)
                remove(f"{self.user.username}-data.pkl")
            except Exception as e:
                print(f"Logout save error: {e}")
        
        if self.client_socket:
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()
            except:
                pass
        self.user = None
        self.client_socket = None
        self.password = None
        self.username = None
