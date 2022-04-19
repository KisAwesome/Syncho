import socket
import threading
import zono.colorlogger
import zono.zonocrypt
import secrets
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.padding
import pynput.keyboard as keyboard
import clipboard
import time

Crypt = zono.zonocrypt.zonocrypt()

objcrypt = zono.zonocrypt.objcrypt(
    hash_algorithm=zono.zonocrypt.objcrypt.SHA512)

# s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# s.connect(('8.8.8.8', 80))
# ipaddr = s.getsockname()[0]
# s.close()

IP = 'localhost'
PORT = 4245
HEADER = 512
FORMAT = 'utf-8'
IP_GLOBAL = IP
KEY_UPPERBOUND = 100000000


ALLOWED_VERSIONS = ('V1.0',)
LATEST_VERSION = 'V1.0'

ADDR_SEESION_KEY = {}
TYPING = {}


ev_sock = None

CONNECTED_ADDRS_TO_SESSION = {}
EVENT_SOCKETS = {}
CONN_ADDR = {}

PATHS_TO_FUNCS = {}

packet = dict

def log(msg, log_type=zono.colorlogger.log):
    log_type(msg)


def send(pkt, conn, address):
    message = objcrypt.encrypt(pkt, ADDR_SEESION_KEY[address])

    msg_length = len(message)

    send_length = str(msg_length).encode(FORMAT)

    send_length += b' ' * (HEADER - len(send_length))

    conn.send(send_length)
    conn.send(message)


def recv(client, address):
    try:
        msg_len = int(client.recv(HEADER).decode(FORMAT))
    except ValueError:
        raise socket.error
    msg = client.recv(msg_len)
    obj = objcrypt.decrypt(msg, ADDR_SEESION_KEY[address])
    return obj


def send_raw(pkt, conn):
    message = objcrypt.encode(pkt)
    msg_length = len(message)

    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))

    conn.send(send_length)
    conn.send(message)


def recv_raw(client):
    msg_len = int(client.recv(HEADER).decode(FORMAT))
    msg = client.recv(msg_len)
    msg = objcrypt.decode(msg)
    return msg


ipaddr = 'localhost'

if IP != ipaddr:
    log(
        f'mismatching ip private address correct ip: {ipaddr},Automaticaly switched to correct ip', log_type=zono.colorlogger.error)
    IP = ipaddr
    IP_GLOBAL = IP


def request(path):
    def wrapper(func):
        PATHS_TO_FUNCS[path] = func

    return wrapper


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((IP, PORT))
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.listen()


def handle_client(conn, addr):
    log(f'{addr} Connected')
    echo_pkt = recv_raw(conn)
    num1 = echo_pkt['num']

    private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    pem = public_key.public_bytes(encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
                                  format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo)

    num2 = secrets.randbelow(KEY_UPPERBOUND)
    send_raw(packet(pem=pem, kdn=num2), conn)

    num_3_enc = recv_raw(conn)['num']

    _num3 = private_key.decrypt(
        num_3_enc,
        cryptography.hazmat.primitives.asymmetric.padding.OAEP(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                algorithm=cryptography.hazmat.primitives.hashes.SHA384()),
            algorithm=cryptography.hazmat.primitives.hashes.SHA384(),
            label=None
        )
    )
    num3 = int(_num3.decode('utf-8'))

    key_deriv = str(num1*num2*num3)

    key = Crypt.hashing_function(key_deriv)
    ADDR_SEESION_KEY[addr] = key
    send(packet(status=200, info='Initiated secure connection'), conn, addr)
    log(f'{addr} Initiated secure connection')
    recv_loop(conn, addr)

def recv_loop(conn, addr):
    while True:
        try:
            pkt = recv(conn, addr)
            path = pkt.get('path', None)
            if path in PATHS_TO_FUNCS:
                PATHS_TO_FUNCS[path](conn, addr, pkt)

            else:
                send(packet(status=404, info='Path not found',error=True), conn, addr)

        except socket.error as e:
            CONNECTED_ADDRS_TO_SESSION.pop(addr,None)
            log(f'{addr} disconnected {e}')
            break

def accept_connections():
    server.listen()
    while True:
        conn, addr = server.accept()
        CONN_ADDR[conn]= addr
        threading.Thread(target=handle_client, args=(conn, addr,)).start()





@request('event_socket')
def ev_sock_register(conn,addr,pkt):
    global ev_sock
    ev_sock= conn

@request('clipboard')
def ev_copy(conn,addr,pkt):
    if pkt['type'] == 'clipboard':
        print(pkt)
        clipboard.copy(pkt['content'])

def copy():
    global ev_sock
    time.sleep(0.01)
    paste = clipboard.paste()
    print(paste)
    if ev_sock:
        send(dict(
            type='clipboard',
            content=paste
        ),ev_sock,CONN_ADDR[ev_sock])

keyboard.GlobalHotKeys({'<cmd>+c':copy}).start()
accept_connections()