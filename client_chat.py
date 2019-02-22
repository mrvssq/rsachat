import socket
import select
import sys
import threading

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

class ReadMSG(Ui_Form):
    def __init__(self, msg):
        print('test')
        self.textEdit.insertPlainText("SERER: " + (msg.decode('utf-8')) + '\n')
        return None

def connect_discconect(ip='127.0.0.1', port_str='8000', onoff=1):
    if onoff == 1:
        port = int(port_str)
        server.connect((ip, port))
        t1 = threading.Thread(target=tread)
        t1.start()
    if onoff == 0:
        server.close()

def tread():
    while True:
        sockets_list = [sys.stdin, server]
        read_sockets, write_socket, error_socket = select.select(sockets_list, [], [])

        for socks in read_sockets:
            if socks == server:
                message = socks.recv(2048)
                #print(message.decode('utf-8'))
                self.textEdit.insertPlainText("SERER: " + (msg.decode('utf-8')) + '\n')
    server.close()

if __name__ == '__main__':
    connect_discconect()
