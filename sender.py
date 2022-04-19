import pynput.keyboard as keyboard
import clipboard
import time
import signal
import SocketTypes
import threading

signal.signal(signal.SIGTRAP,lambda x,y:x)

addr = ('localhost',4245)

socket = SocketTypes.SecureSocket(addr)
eventSocket = SocketTypes.SecureSocket(addr)

def event_loop():
    eventSocket.send(dict(
        path='event_socket'
    ))
    while True:
        event = eventSocket.recv()
        if not event:
            continue
        if event['type'] == 'clipboard':
            print(event)
            clipboard.copy(event['content'])

def copy():
    time.sleep(0.01)
    paste = clipboard.paste()
    print(paste)
    socket.send(dict(
        path='clipboard',
        type='clipboard',
        content=paste
    ))


threading.Thread(target=event_loop).start()

with keyboard.GlobalHotKeys({'<cmd>+c':copy}) as l:
    l.join()