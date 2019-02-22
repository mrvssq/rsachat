from test_ui import Ui_Form
from PyQt5.QtCore import pyqtSignal, QThread
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from tkinter import *
import base64
import hashlib
import datetime
import socket
import random
import json
import time


class WorkThread(QThread):
    reply_server = pyqtSignal(dict)

    def __init__(self, server, key):
        super().__init__()
        self.server = server
        key_bytes = bytes(key, "utf8")
        self.key = RSA.importKey(key_bytes)

    def run(self):
        while True:
            try:
                message_json = self.server.recv(4096)
                if message_json:
                    commands = message_json[7:-5].split(b'}end}{begin{')
                    for command in commands:
                        command_right = self.command_handler(command)
                        if command_right is not None:
                            self.reply_server.emit(command_right)
                else:
                    error = 'Error Disconnect server'
                    self.reply_server.emit({'command': '-sError', 'error': error})
                    break
            except Exception as error:
                errorMSG = 'error cycle "while": ' + str(error)
                error_send = {'command': '-sError', 'error': errorMSG}
                self.reply_server.emit(error_send)
                break
        print('exit cycle "while" / disconnect server')
        return None

    def command_handler(self, command):
        try:
            if command:
                command_with_json = b''
                blocks = command[11:-11].split(b'--[SPLIT]--')
                for block in blocks:
                    command_with_json += self.key.decrypt(block)
                command_right = json.loads(command_with_json.decode('utf-8'))
                print(command_right)
                return command_right
        except Exception as error:
            errorMSG = 'error "command_handler": ' + str(error)
            error_send = {'command': '-sError', 'error': errorMSG}
            self.reply_server.emit(error_send)
            return None


class MainWindowSlots(Ui_Form):
    random_generator = Random.new().read
    keys_me = {'publicKey': None, 'privateKey': None}
    key_server = None
    key_aes_room = None
    keys_clients = {1: None, 0: None}
    room_now = None

    def button_connect(self):
        self.gen_random_nickname()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = self.lineEdit_1.text()
        port_str = self.lineEdit_2.text()
        self.groupBox.setEnabled(False)
        self.pushButton_10.setEnabled(False)
        self.pushButton_2.setEnabled(False)
        self.lineEdit_3.setEnabled(True)
        self.pushButton.setEnabled(True)
        self.pushButton_6.setEnabled(True)
        self.pushButton_3.setEnabled(True)
        self.tabWidget.setCurrentIndex(0)
        self.first_connect(host, port_str)
        return None

    def button_disconnect(self):
        self.stop_cycle()
        message = 'Desconnected from the server'
        self.disconnect(message)
        return None

    def disconnect(self, message):
        self.stop_cycle()
        self.room_now = None
        self.keys_me = {'publicKey': None, 'privateKey': None}
        self.key_server = None
        self.key_aes_room = None
        self.keys_clients = {1: None, 0: None}
        self.server.close()
        self.listWidget.clear()
        self.listWidget_2.clear()
        self.label_3.setText('your id: ')
        self.label_17.setText('<html><head/><body><p align="center">-</p></body></html>')
        self.textEdit_4.setText('')
        self.textEdit_5.setText('')
        self.textEdit_6.setText('')
        self.textEdit_7.setText('')
        self.textEdit_8.setText('')
        self.pushButton_10.setEnabled(False)
        self.pushButton.setEnabled(False)
        self.pushButton_3.setEnabled(False)
        self.pushButton_6.setEnabled(False)
        self.lineEdit_3.setEnabled(False)
        self.pushButton_2.setEnabled(True)
        self.groupBox.setEnabled(True)
        self.command_dict_handler({'command': '-sDisconnect', 'info': message})
        return None

    def button_create_new_room(self):
        self.lineEdit_3.setEnabled(False)
        self.pushButton_6.setEnabled(False)

        name_room = self.lineEdit_3.text()
        self.lineEdit_3.setText('')
        data_send = {'command': '-sNewRoom', 'name_room': name_room}
        self.send_to_server(data_send)
        return None

    def button_exit_room(self):
        self.pushButton_10.setEnabled(False)
        data_send = {'command': '-sExitRoom'}
        self.send_to_server(data_send)
        return None

    def double_clicked_widget2_add_new_user_in_room(self):
        id_client = self.listWidget_2.currentItem().text()
        self.listWidget_2.takeItem(self.listWidget_2.currentRow())

        publicKeyClient = self.keys_clients[int(id_client)]
        self.textEdit_8.insertHtml("<font color=\"green\">Public_Key client " + str(id_client) +
                                   ":<br>" + str(publicKeyClient) + "</font><br>")
        self.textEdit_8.insertHtml("<font color=\"black\">=================================</font><br>")

        key_rsa_bytes = bytes(str(publicKeyClient), "utf8")
        rightKeyPublicClient = RSA.importKey(key_rsa_bytes)
        cryptAES256 = rightKeyPublicClient.encrypt(self.key_aes_room, self.random_generator)
        data_send = {'command': '-sResolutionAdmin', 'response': 1, 'id': id_client,
                     'cryptPrivatkey': str(cryptAES256[0].hex())}
        self.send_to_server(data_send)
        return None

    def double_clicked_widget_in_room(self):
        if self.room_now is None:
            self.pushButton_6.setEnabled(False)
            self.lineEdit_3.setEnabled(False)
            name_room = self.listWidget.currentItem().text()
            if (self.keys_me['publicKey'] is None) or (self.keys_me['privateKey'] is None):
                self.gen_rsa_kes()
            data_send = {'command': '-sGo', 'name_room': str(name_room),
                         'publicKey': str(self.keys_me['publicKey'].decode('utf-8'))}
            self.send_to_server(data_send)
        else:
            kick_id = self.listWidget.currentItem().text()
            data_send = {'command': '-sKickUser', 'kick_id': kick_id}
            self.send_to_server(data_send)
        return None

    def button_gen_rsa_keys(self):
        self.gen_rsa_kes()
        return None

    def button_gen_aes_keys(self):
        self.gen_aes_kes()
        return None

    def button_hand_gen_random_number_keys(self):
        root = Tk()
        if self.lineEdit_5.text() == '':
            x = root.winfo_pointerx()
            y = root.winfo_pointery()
            summ = str(hex(x)) + str(hex(y))
            len1 = random.randint(256, 512)
            len2 = random.randint(256, 512)
            by = str(Random.get_random_bytes(len1).hex()) + summ + str(Random.get_random_bytes(len2).hex())
            self.textEdit_2.setText(by)
        return None

    def gen_aes_kes(self):
        if self.textEdit_2.toPlainText() == '':
            random_sha_256 = Random.get_random_bytes(512)
            self.textEdit_2.setText(str(random_sha_256.hex()))
        else:
            random_sha_256 = bytes(self.textEdit_2.toPlainText(), 'utf-8')
        keyAES256 = hashlib.sha256(random_sha_256).digest()
        self.key_aes_room = keyAES256
        self.textEdit_7.setText(str(keyAES256.hex()))
        return None

    def gen_rsa_kes(self):
        bit = int(self.comboBox.currentText())
        if self.textEdit_2.toPlainText() == '':
            random_generator = Random.new().read
        else:
            random_generator = Random.new().read
        privateKey = RSA.generate(bit, random_generator)
        publicKey = privateKey.publickey()

        self.keys_me['publicKey'] = publicKey.exportKey()
        self.keys_me['privateKey'] = privateKey.exportKey()

        self.textEdit_4.setText(str(publicKey.exportKey().decode('utf-8')))
        return None

    def button_send_msg(self):
        if self.lineEdit.toPlainText() != '':
            text_msg = self.lineEdit.toPlainText().replace('\n', '<br>')
            self.lineEdit.setPlainText('')
            msg_blocks = []
            length_msg = 2000
            if len(text_msg) > length_msg:
                msg_blocks = self.divided_into_teams(text_msg, length_msg)
            else:
                msg_blocks.append(text_msg)
            for one_msg in msg_blocks:
                if len(msg_blocks) >= 3:
                    time.sleep(1)
                my_self_msg = {'command': '-sYourmsg', 'message': one_msg}
                self.command_dict_handler(my_self_msg)
                msg_crypto = self.encrypt_msg_aes(one_msg)
                msg_send = {'command': '-sMsg', 'message': msg_crypto}
                self.send_to_server(msg_send)
        return None

    @staticmethod
    def divided_into_teams(text_msg, length_msg):
        msg_blocks = []
        while len(text_msg) > length_msg:
            one = text_msg[:length_msg]
            msg_blocks.append(one)
            text_msg = text_msg[length_msg:]
        msg_blocks.append(text_msg)
        return msg_blocks

    def encrypt_msg_aes(self, text_msg):
        try:
            key256 = self.key_aes_room
            BLOCK_SIZE = 32
            if key256 is None:
                return text_msg
            else:
                text_msg = text_msg + (BLOCK_SIZE - len(text_msg) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(text_msg) % BLOCK_SIZE)
                iv = Random.new().read(AES.block_size)
                cipher = AES.new(key256, AES.MODE_CBC, iv)
                msg_crypto = base64.b64encode(iv + cipher.encrypt(text_msg))
                return msg_crypto.decode('utf-8')
        except Exception as error:
            errorMSG = 'error "encrypt_msg_aes": ' + str(error)
            error_send = {'command': '-sError', 'error': errorMSG}
            self.command_dict_handler(error_send)

    def decrypt_msg_aes(self, text_msg):
        try:
            key256 = self.key_aes_room
            if key256 is None:
                return text_msg
            else:
                enc = base64.b64decode(text_msg)
                iv = enc[:AES.block_size]
                cipher = AES.new(key256, AES.MODE_CBC, iv)
                s = cipher.decrypt(enc[AES.block_size:]).decode('utf-8')
                msg_crypto = s[:-ord(s[len(s) - 1:])]
                return msg_crypto
        except Exception as error:
            errorMSG = 'error "decrypt_msg_aes": ' + str(error)
            error_send = {'command': '-sError', 'error': errorMSG}
            self.command_dict_handler(error_send)

    def send_to_server(self, message):
        try:
            message_json = json.dumps(message)
            send_msg = self.cryptoRSAforServer(message_json)
            if len(send_msg) < 4096:
                self.server.send(send_msg)
            else:
                error = {'command': '-sError', 'error': 'len command have big size'}
                self.command_dict_handler(error)
        except Exception as error:
            errorMSG = 'error "send to server": ' + str(error)
            error_send = {'command': '-sError', 'error': errorMSG}
            self.disconnect(error_send)

    def cryptoRSAforServer(self, message_json):
        try:
            key_bytes = bytes(self.key_server, "utf8")
            key = RSA.importKey(key_bytes)

            send_msg = b'{begin{--[SPLIT]--'
            if len(message_json) > 250:
                i = 0
                while len(message_json) > 250:
                    enterMSG = message_json[:250]
                    message_send = key.encrypt(bytes(enterMSG, "utf8"), self.random_generator)
                    send_msg += message_send[0] + b'--[SPLIT]--'
                    message_json = message_json[250:]
                    i += 1
            message_send = key.encrypt(bytes(message_json, "utf8"), self.random_generator)
            send_msg += message_send[0] + b'--[SPLIT]--}end}'
            return send_msg
        except Exception as error:
            errorMSG = 'error "cryptoRSAforServer": ' + str(error)
            error_send = {'command': '-sError', 'error': errorMSG}
            self.command_dict_handler(error_send)
            return None

    def gen_random_nickname(self):
        if self.lineEdit_9.text() == '':
            nick = random.randint(10000, 99999)
            self.lineEdit_9.setText('nick' + str(nick))
        return None

    def first_connect(self, host='127.0.0.1', port_str='8000'):
        if (self.keys_me['publicKey'] is None) or (self.keys_me['privateKey'] is None):
            self.gen_rsa_kes()
        nickname = self.lineEdit_9.text()
        first_msg = {'command': '-sFirstConnect', 'nickname': nickname,
                     'publicKey': self.keys_me['publicKey'].decode('utf-8')}
        try:
            port = int(port_str)
            self.server.connect((host, port))
            self.workThread = WorkThread(self.server, self.keys_me['privateKey'].decode('utf-8'))
            self.workThread.reply_server.connect(self.command_dict_handler)
            self.workThread.start()
            message = json.dumps(first_msg)
            self.server.send(bytes(message, "utf8"))
        except Exception as error:
            errorMSG = 'error "first_connect": ' + str(error)
            error_send = {'command': '-sError', 'error': errorMSG}
            self.disconnect(error_send)
            return None

    def stop_cycle(self):
        try:
            if not self.workThread.wait(1):
                self.workThread.terminate()
        except:
            print('cycle not found')
        return None

    def write_in_window(self, color, text, prefix):
        time_chat = str(datetime.datetime.now().time())
        time_chat = '<font color=\"black\">[' + time_chat[:8] + ']</font>'
        self.textEdit_Global.insertHtml(
            "<font color=\"" + color + "\">" + time_chat + prefix + ": " + str(text) + "</font><br>")
        cursor = self.textEdit_Global.textCursor()
        self.textEdit_Global.setTextCursor(cursor)

    def command_dict_handler(self, data):
        if data['command'] == '-sRooms':
            self.add_items_to_widget(data['rooms'])
        elif data['command'] == '-sExitRoom':
            self.exit_room(data)
        elif data['command'] == '-sOnline':
            self.add_items_to_widget(data['users'])
        elif data['command'] == '-sNewRoom':
            self.yesiaminroom(data)
        elif data['command'] == '-sDisconnect':
            self.write_in_window('red', data['info'], 'SYSTEM')
        elif data['command'] == '-sMsg':
            self.accept_message(data)
        elif data['command'] == '-sYourmsg':
            self.myself_msg(data)
        elif data['command'] == '-sFirstRequest':
            self.FirstRequest(data)
        elif data['command'] == '-sResolutionAdmin':
            self.ResolutionAdmin(data)
        elif data['command'] == '-sRefreshRequests':
            self.RefreshRequests(data)
        elif data['command'] == '-sInvitationRoom':
            self.invitation_room(data)
        elif data['command'] == '-sError':
            self.error_command(data)
        else:
            self.write_in_window('red', data, 'ERROR COMMAND')
        return None

    def add_items_to_widget(self, items):
        self.listWidget.clear()
        for i in items:
            self.listWidget.addItem(str(i))
        self.listWidget.sortItems()
        return None

    def exit_room(self, data):
        name_room = data['name']
        self.room_now = None
        self.key_aes_room = None
        self.textEdit_7.setText('')
        self.label_17.setText('<html><head/><body><p align="center">-</p></body></html>')
        self.pushButton_6.setEnabled(True)
        self.lineEdit_3.setEnabled(True)
        self.pushButton_10.setEnabled(False)
        if data['indicator'] == 'exit':
            msg_view = "You left the room: " + name_room
            self.write_in_window('purple', msg_view, 'SERVER')
        elif data['indicator'] == 'kick':
            msg_view = "You were kicked from the room: " + name_room
            self.write_in_window('red', msg_view, 'SERVER')
        return None

    def yesiaminroom(self, data):
        if data['error'] == '0':
            if self.key_aes_room is None:
                self.gen_aes_kes()
            self.pushButton_10.setEnabled(True)
            self.pushButton_6.setEnabled(False)
            self.lineEdit_3.setEnabled(False)
            name_room = data['name_room']
            self.room_now = data['name_room']
            self.label_17.setText('<html><head/><body><p align="center">' + name_room + '</p></body></html>')

            publicKey = self.keys_me['publicKey']
            self.textEdit_8.insertHtml("<font color=\"red\">Public_Key client ADMIN" +
                                       ":<br>" + str(publicKey) + "</font><br>")
            self.textEdit_8.insertHtml("<font color=\"black\">=================================</font><br>")
        else:
            self.pushButton_6.setEnabled(True)
            self.lineEdit_3.setEnabled(True)
            self.pushButton_10.setEnabled(False)
            error = data['error']
            self.command_dict_handler({'command': '-sError', 'error': str(error)})
        return None

    def accept_message(self, data):
        nick = data['nickname']
        id_client = str(data['id'])
        msg_view = self.decrypt_msg_aes(data['message'])
        prefix = '<font color=\"grey\">' + nick + '(' + id_client + ')</font>'
        self.write_in_window('black', msg_view, prefix)
        return None

    def myself_msg(self, data):
        myself_msg = data['message']
        prefix = "<font color=\"blue\">You</font>"
        self.write_in_window('black', myself_msg, prefix)
        return None

    def FirstRequest(self, message):
        if message['error'] != '0':
            error = message['error']
            nickname = message['nickname']
            msg_view = error
            self.write_in_window('red', msg_view, 'SERVER')
            msg_view = "You new nickname: " + nickname
            self.write_in_window('green', msg_view, 'SERVER')
            self.lineEdit_9.setText(nickname)
        welcome = message['welcome']
        self.key_server = message['PublicKeyServer']
        self.textEdit_6.setText(self.key_server)
        self.write_in_window('green', welcome, 'SERVER')
        self.add_items_to_widget(message['rooms'])
        self.label_3.setText('your id: ' + message['id'])
        return None

    def ResolutionAdmin(self, data):
        id_client = data['id']
        publicKeyClient = data['publicKey']
        self.keys_clients[int(id_client)] = publicKeyClient
        requests = data['requests']
        self.listWidget_2.clear()
        for i in requests:
            self.listWidget_2.addItem(str(i))
        prefix = "Room(" + self.room_now + ")"
        msg_view = "client " + id_client + " wants to connect to the room"
        self.write_in_window('purple', msg_view, prefix)
        return None

    def RefreshRequests(self, data):
        requests = data['requests']
        self.listWidget_2.clear()
        for i in requests:
            self.listWidget_2.addItem(str(i))
        return None

    def invitation_room(self, data):
        if data['error'] == 0:
            self.pushButton_10.setEnabled(True)
            self.pushButton_6.setEnabled(False)
            self.lineEdit_3.setEnabled(False)
            name_room = data['name_room']
            self.room_now = name_room
            welcome = data['welcome']
            prefix = "Room(" + self.room_now + ")"
            self.write_in_window('purple', welcome, prefix)
            CryptPrivatKeyRoom = bytes.fromhex(data['CryptPrivatKeyRoom'])
            private_key = RSA.importKey(self.keys_me['privateKey'])
            PrivatKeyRoom = private_key.decrypt(CryptPrivatKeyRoom)

            self.key_aes_room = PrivatKeyRoom
            self.textEdit_7.setText(str(PrivatKeyRoom.hex()))
            self.label_17.setText('<html><head/><body><p align="center">' + name_room + '</p></body></html>')
        return None

    def error_command(self, data):
        error = str(data['error'])
        if error == 'Error Disconnect server':
            self.disconnect(error)
        else:
            self.write_in_window('red', error, 'ERROR')
        return None
