import secrets
import socket
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.padding
import zono.zonocrypt


Crypt = zono.zonocrypt.zonocrypt()

objcrypt = zono.zonocrypt.objcrypt(
    hash_algorithm=zono.zonocrypt.objcrypt.SHA512)


HEADER = 512
FORMAT = 'utf-8'
KEY_UPPERBOUND = 100000000

class SecureSocket:
    def __init__(self,addr):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(addr)
        num1 = secrets.randbelow(KEY_UPPERBOUND)
        self.send_raw(self.packet(num=num1))
        pkt = self.recv_raw()
        num2 = pkt['kdn']
        _pem = pkt['pem']
        public_key = cryptography.hazmat.primitives.serialization.load_pem_public_key(
            _pem)

        num3 = secrets.randbelow(KEY_UPPERBOUND)


        num3_enc = public_key.encrypt(
            str(num3).encode('utf-8'),
            cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                    algorithm=cryptography.hazmat.primitives.hashes.SHA384()),
                algorithm=cryptography.hazmat.primitives.hashes.SHA384(),
                label=None
            )
        )
        self.send_raw(self.packet(num=num3_enc))

        key_deriv = str(num1*num2*num3)
        self.session_key = Crypt.hashing_function(key_deriv)
        status = self.recv()

        
    def packet(self,**kwargs):
        pkt = {}
        for k, v in kwargs.items():
            pkt[k] = v

        return pkt

    def send(self,pkt):
        message = objcrypt.encrypt(pkt, self.session_key)

        msg_length = len(message)

        send_length = str(msg_length).encode(FORMAT)

        send_length += b' ' * (HEADER - len(send_length))

        self.socket.send(send_length)
        self.socket.send(message)


    def recv(self):
        msg_len = int(self.lient.recv(HEADER).decode(FORMAT))
        msg = self.socket.recv(msg_len)
        obj = objcrypt.decrypt(msg, self.session_key)
        return obj


    def send_raw(self,pkt):
        message = objcrypt.encode(pkt)
        msg_length = len(message)

        send_length = str(msg_length).encode(FORMAT)
        send_length += b' ' * (HEADER - len(send_length))

        self.socket.send(send_length)
        self.socket.send(message)


    def recv_raw(self):
        msg_len = int(self.socket.recv(HEADER).decode(FORMAT))
        msg = self.socket.recv(msg_len)
        msg = objcrypt.decode(msg)
        return msg


    def recv(self):
        msg_len = int(self.socket.recv(HEADER).decode(FORMAT))
        msg = self.socket.recv(msg_len)
        obj = objcrypt.decrypt(msg, self.session_key)
        return obj
