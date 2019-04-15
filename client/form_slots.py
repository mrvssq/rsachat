from form_ui import Ui_formrsachat
from work_thread import WorkThread
from PyQt5.QtGui import QTextCursor
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import random
from Crypto.Cipher import AES
import base64
import hashlib
import datetime
import socket
import json
import time


def genAES(numbers=None):
    if numbers is None:
        randomSHA256 = Random.get_random_bytes(512)
    else:
        randomSHA256 = bytes(numbers, 'utf-8')
    keyAES256 = hashlib.sha256(randomSHA256).digest()
    return keyAES256


def genRSA(bit, randomGenerator):
    privateKey = RSA.generate(bit, randomGenerator)
    publicKey = privateKey.publickey()
    return {'publicKey': publicKey.exportKey(), 'privateKey': privateKey.exportKey()}


class MainWindowSlots(Ui_formrsachat):
    server = None
    myKeysRSA = {'publicKey': None, 'privateKey': None}
    serverKey = None
    roomKeyAES = None
    clientKeys = {1: None, 0: None}
    roomNow = None
    randomPointsArt = None

    def __init__(self):
        self.workThreadClient = None

    def genRandomNickname(self):
        if self.lineEditNickName.text() == '':
            nick = random.randint(10000, 99999)
            self.lineEditNickName.setText('nick' + str(nick))
        return None

    def buttonConnect(self):
        try:
            self.genRandomNickname()
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host = self.lineEditHost.text()
            port = self.lineEditPort.text()
        except Exception as errorTry:
            errorMsg = 'buttonConnect. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
            return None
        self.groupBoxHostPortNick.setEnabled(False)
        self.pushButtonExitRoom.setEnabled(False)
        self.pushButtonConnect.setEnabled(False)
        self.groupBoxGenKeysRSA.setEnabled(False)
        self.lineEditNameNewRoom.setEnabled(True)
        self.pushButtonDisconnect.setEnabled(True)
        self.pushButtonCreateRoom.setEnabled(True)
        self.pushButtonSendMsg.setEnabled(True)
        self.tabWidget.setCurrentIndex(0)
        self.firstConnect(host, port)
        return None

    def buttonDisconnect(self):
        self.stopCycle()
        message = 'Disconnected from the server'
        self.disconnectAlgorithm(message)
        return None

    def disconnectAlgorithm(self, message):
        try:
            self.server.close()
            self.stopCycle()
        except Exception as errorTry:
            errorMsg = 'disconnectAlgorithm. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
            return None
        self.roomNow = None
        self.myKeysRSA = {'publicKey': None, 'privateKey': None}
        self.serverKey = None
        self.roomKeyAES = None
        self.clientKeys = {1: None, 0: None}
        self.listWidgetRooms.clear()
        self.listWidgetRequests.clear()
        self.labelYourID.setText('your id: ')
        self.labelNameRoom.setText('<html><head/><body><p align="center">-</p></body></html>')
        self.textEditMyPublicKeyRSA.setText('')
        self.textEditMyPrivatKeyRSA.setText('')
        self.textEditPublicKeyServer.setText('')
        self.textEditKeyRoomAES.setText('')
        self.textEditPublicKeysClients.setText('')
        self.pushButtonExitRoom.setEnabled(False)
        self.pushButtonDisconnect.setEnabled(False)
        self.pushButtonSendMsg.setEnabled(False)
        self.pushButtonCreateRoom.setEnabled(False)
        self.lineEditNameNewRoom.setEnabled(False)
        self.pushButtonConnect.setEnabled(True)
        self.groupBoxGenKeysRSA.setEnabled(True)
        self.groupBoxHostPortNick.setEnabled(True)
        self.pushButtonGenAES.setEnabled(True)

        self.comandsHandler({'command': '-sDisconnect', 'info': message})
        return None

    def buttonCreateNewRoom(self):
        self.lineEditNameNewRoom.setEnabled(False)
        self.pushButtonCreateRoom.setEnabled(False)
        self.pushButtonGenAES.setEnabled(False)

        nameRoom = self.lineEditNameNewRoom.text()
        self.lineEditNameNewRoom.setText('')
        dataToSend = {'command': '-sNewRoom', 'name_room': nameRoom}
        self.sendToServer(dataToSend)
        return None

    def buttonExitRoom(self):
        self.pushButtonExitRoom.setEnabled(False)
        dataToSend = {'command': '-sExitRoom'}
        self.sendToServer(dataToSend)
        return None

    def doubleClickedWidgetRequests(self):
        try:
            clientID = self.listWidgetRequests.currentItem().text()
            self.listWidgetRequests.takeItem(self.listWidgetRequests.currentRow())

            publicKeyClient = self.clientKeys[int(clientID)]
            self.textEditPublicKeysClients.insertHtml("<font color=\"green\">Public_Key client " + str(clientID) +
                                                      ":<br>" + str(publicKeyClient) + "</font><br>")
            self.textEditPublicKeysClients.insertHtml("<font color=\"black\">=============================</font><br>")

            pubKeyBytesRSA = bytes(str(publicKeyClient), "utf8")
            rightKeyPublicClient = RSA.importKey(pubKeyBytesRSA)
            cryptAES256 = rightKeyPublicClient.encrypt(self.roomKeyAES, self.randomGeneratorPointsArt)
            dataToSend = {'command': '-sResolutionAdmin', 'response': 1, 'id': clientID,
                          'cryptPrivatkey': str(cryptAES256[0].hex())}
            self.sendToServer(dataToSend)
        except Exception as errorTry:
            errorMsg = 'doubleClickedWidgetRequests. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
            return None
        return None

    def doubleClickedWidgetOnline(self):
        if self.roomNow is None:
            self.pushButtonCreateRoom.setEnabled(False)
            self.pushButtonGenAES.setEnabled(False)
            self.lineEditNameNewRoom.setEnabled(False)
            nameRoom = self.listWidgetRooms.currentItem().text()
            if (self.myKeysRSA['publicKey'] is None) or (self.myKeysRSA['privateKey'] is None):
                self.buttonGenKeysRSA()
            dataToSend = {'command': '-sGo', 'name_room': str(nameRoom),
                          'publicKey': str(self.myKeysRSA['publicKey'].decode('utf-8'))}
            self.sendToServer(dataToSend)
        else:
            kickID = self.listWidgetRooms.currentItem().text()
            dataToSend = {'command': '-sKickUser', 'kick_id': kickID}
            self.sendToServer(dataToSend)
        return None

    def buttonGenKeysRSA(self):
        try:
            bit = int(self.comboBoxBitRSA.currentText())
            keysRSA = genRSA(bit, self.randomGeneratorPointsArt)
            self.myKeysRSA['publicKey'] = keysRSA['publicKey']
            self.myKeysRSA['privateKey'] = keysRSA['privateKey']
            self.textEditMyPublicKeyRSA.setText(str(keysRSA['publicKey'].decode('utf-8')))
            self.textEditMyPrivatKeyRSA.setText(str(keysRSA['privateKey'].decode('utf-8')))
        except Exception as errorTry:
            errorMsg = 'buttonGenKeysRSA. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
            return None
        return None

    def buttonGenKeyAES(self):
        try:
            keyAES256 = genAES(self.randomPointsArt)
            self.roomKeyAES = keyAES256
            self.textEditKeyRoomAES.setText(str(keyAES256.hex()))
        except Exception as errorTry:
            errorMsg = 'buttonGenKeyAES. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
            return None
        return None

    def randomGeneratorPointsArt(self, n):
        if self.randomPointsArt is None:
            return Random.get_random_bytes(n)
        else:
            sumBytes = bytes(self.randomPointsArt, encoding='utf-8')
        arr = [byte for byte in sumBytes]
        Random.random.shuffle(arr)
        sumBytes = bytes(arr)
        count = n - len(sumBytes)
        if count > 0:
            sumBytes = sumBytes + Random.get_random_bytes(count)
        if count < 0:
            sumBytes = sumBytes[:n]
        return sumBytes

    def buttonSendMessage(self):
        try:
            if self.lineEditSendMsg.toPlainText() != '':
                textMSG = self.lineEditSendMsg.toPlainText().replace('\n', '<br>')
                self.lineEditSendMsg.setPlainText('')
                lengthMSG = 2000
                blocksMSG = [textMSG[i:i+lengthMSG] for i in range(0, len(textMSG), lengthMSG)]
                for message in blocksMSG:
                    if len(blocksMSG) >= 3:
                        time.sleep(1)
                    mySelfMSG = {'command': '-sYourmsg', 'message': message}
                    self.comandsHandler(mySelfMSG)
                    cryptoMSG = self.encryptTextToAES(message)
                    dataToSend = {'command': '-sMsg', 'message': cryptoMSG}
                    self.sendToServer(dataToSend)
        except Exception as errorTry:
            errorMsg = 'buttonSendMessage. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
            return None
        return None

    def encryptTextToAES(self, message):
        try:
            key256 = self.roomKeyAES
            if (key256 is None) or (self.roomNow is None):
                return message
            else:
                BS = 16
                message = message + (BS - len(message) % BS) * chr(BS - len(message) % BS)
                iv = Random.new().read(AES.block_size)
                cipher = AES.new(key256, AES.MODE_CFB, iv)
                enc = base64.b64encode(iv + cipher.encrypt(message)).decode('utf-8')
                return enc
        except Exception as errorTry:
            errorMsg = 'encryptTextToAES. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)

        return None

    def decryptTextFromAES(self, message):
        try:
            key256 = self.roomKeyAES
            if (key256 is None) or (self.roomNow is None):
                return message
            else:
                BS = 16
                enc = base64.b64decode(message)
                iv = enc[:BS]
                cipher = AES.new(key256, AES.MODE_CFB, iv)
                s = cipher.decrypt(enc[AES.block_size:]).decode('utf-8')
                return s[0:-ord(s[-1])]
        except Exception as errorTry:
            errorMsg = 'decryptTextFromAES. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
        return None

    def sendToServer(self, message):
        try:
            messageJson = json.dumps(message)
            sendMSG = self.cryptoForServerRSA(messageJson)
            if len(sendMSG) < 4096:
                self.server.send(sendMSG)
            else:
                errorMsg = 'send_to_server. error: len command have big size'
                errorSend = {'command': '-sError', 'type': 'none', 'error': errorMsg}
                self.comandsHandler(errorSend)
        except Exception as errorTry:
            errorMsg = 'sendToServer. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
        return None

    def cryptoForServerRSA(self, messageJson):
        try:
            serverKey = bytes(self.serverKey, "utf8")
            key = RSA.importKey(serverKey)
            sendMSG = b'{begin{--[SPLIT]--'
            if len(messageJson) > 250:
                i = 0
                while len(messageJson) > 250:
                    enterMSG = messageJson[:250]
                    message = key.encrypt(bytes(enterMSG, "utf8"), self.randomGeneratorPointsArt)
                    sendMSG += message[0] + b'--[SPLIT]--'
                    messageJson = messageJson[250:]
                    i += 1
            message = key.encrypt(bytes(messageJson, "utf8"), self.randomGeneratorPointsArt)
            sendMSG += message[0] + b'--[SPLIT]--}end}'
            return sendMSG
        except Exception as errorTry:
            errorMsg = 'cryptoForServerRSA. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
        return None

    def firstConnect(self, host='127.0.0.1', portStr='8000'):
        if (self.myKeysRSA['publicKey'] is None) or (self.myKeysRSA['privateKey'] is None):
            self.buttonGenKeysRSA()
        nickname = self.lineEditNickName.text()
        dataToSend = {'command': '-sFirstConnect', 'nickname': nickname,
                      'publicKey': self.myKeysRSA['publicKey'].decode('utf-8')}
        try:
            port = int(portStr)
            self.server.connect((host, port))
            self.workThreadClient = WorkThread(self.server, self.myKeysRSA['privateKey'].decode('utf-8'))
            self.workThreadClient.replyServer.connect(self.comandsHandler)
            self.workThreadClient.start()
            message = json.dumps(dataToSend)
            self.server.send(bytes(message, "utf8"))
        except Exception as errorTry:
            errorMsg = 'firstConnect. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
        return None

    def stopCycle(self):
        try:
            if not self.workThreadClient.wait(1):
                self.workThreadClient.terminate()
                print('workThreadClient.terminate()')
        except Exception as errorTry:
            errorMsg = 'stopCycle. try: ' + str(errorTry)
            errorSend = {'command': '-sError', 'type': 'try', 'error': errorMsg}
            self.comandsHandler(errorSend)
        return None

    def writeInGlobalWindow(self, color, text, prefix):
        timeChat = str(datetime.datetime.now().time())
        timeChat = '<font color=\"black\">[' + timeChat[:8] + ']</font>'
        cursor = self.textEditGlobal.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.textEditGlobal.setTextCursor(cursor)
        self.textEditGlobal.insertHtml(
            "<font color=\"" + color + "\">" + timeChat + prefix + ": " + str(text) + "</font><br>")
        cursor = self.textEditGlobal.textCursor()
        self.textEditGlobal.setTextCursor(cursor)
        return None

    def comandsHandler(self, data):
        if data['command'] == '-sRooms':
            self.addItemsToWidget(data['rooms'])
        elif data['command'] == '-sExitRoom':
            self.exitRoom(data)
        elif data['command'] == '-sOnline':
            self.addItemsToWidget(data['users'])
        elif data['command'] == '-sNewRoom':
            self.responseCreateNewRoom(data)
        elif data['command'] == '-sDisconnect':
            self.writeInGlobalWindow('red', data['info'], 'SYSTEM')
        elif data['command'] == '-sMsg':
            self.acceptMessage(data)
        elif data['command'] == '-sYourmsg':
            self.myselfMSG(data)
        elif data['command'] == '-sFirstRequest':
            self.firstRequest(data)
        elif data['command'] == '-sResolutionAdmin':
            self.resolutionAdmin(data)
        elif data['command'] == '-sRefreshRequests':
            self.refreshRequests(data)
        elif data['command'] == '-sInvitationRoom':
            self.invitationRoom(data)
        elif data['command'] == '-sError':
            self.errorCommand(data)
        else:
            self.writeInGlobalWindow('red', data, 'ERROR COMMAND')
        return None

    def addItemsToWidget(self, items):
        self.listWidgetRooms.clear()
        for item in items:
            self.listWidgetRooms.addItem(str(item))
        self.listWidgetRooms.sortItems()
        return None

    def exitRoom(self, data):
        nameRoom = data['name']
        self.roomNow = None
        self.roomKeyAES = None
        self.textEditKeyRoomAES.setText('')
        self.labelNameRoom.setText('<html><head/><body><p align="center">-</p></body></html>')
        self.pushButtonCreateRoom.setEnabled(True)
        self.lineEditNameNewRoom.setEnabled(True)
        self.pushButtonExitRoom.setEnabled(False)
        self.pushButtonGenAES.setEnabled(True)
        if data['indicator'] == 'exit':
            msgView = "You left the room: " + nameRoom
            self.writeInGlobalWindow('purple', msgView, 'SERVER')
        elif data['indicator'] == 'kick':
            msgView = "You were kicked from the room: " + nameRoom
            self.writeInGlobalWindow('red', msgView, 'SERVER')
        return None

    def responseCreateNewRoom(self, data):
        if data['error'] == 'valid room name':
            if self.roomKeyAES is None:
                self.buttonGenKeyAES()
            self.pushButtonExitRoom.setEnabled(True)
            self.pushButtonCreateRoom.setEnabled(False)
            self.lineEditNameNewRoom.setEnabled(False)
            self.pushButtonGenAES.setEnabled(False)
            nameRoom = data['name_room']
            self.roomNow = data['name_room']
            self.labelNameRoom.setText('<html><head/><body><p align="center">' + nameRoom + '</p></body></html>')

            publicKey = self.myKeysRSA['publicKey']
            self.textEditPublicKeysClients.insertHtml("<font color=\"red\">Public_Key client ADMIN" +
                                                      ":<br>" + str(publicKey) + "</font><br>")
            self.textEditPublicKeysClients.insertHtml(
                "<font color=\"black\">=================================</font><br>")
        else:
            self.pushButtonCreateRoom.setEnabled(True)
            self.lineEditNameNewRoom.setEnabled(True)
            self.pushButtonGenAES.setEnabled(True)
            self.pushButtonExitRoom.setEnabled(False)
            error = data['error']
            errorMsg = 'responseCreateNewRoom. error: ' + str(error)
            errorSend = {'command': '-sError', 'type': 'none', 'error': errorMsg}
            self.comandsHandler(errorSend)
        return None

    def acceptMessage(self, data):
        nick = data['nickname']
        clientID = str(data['id'])
        msgView = self.decryptTextFromAES(data['message'])
        prefix = '<font color=\"grey\">' + nick + '(' + clientID + ')</font>'
        self.writeInGlobalWindow('black', msgView, prefix)
        return None

    def myselfMSG(self, data):
        myselfMSG = data['message']
        prefix = "<font color=\"blue\">You</font>"
        self.writeInGlobalWindow('black', myselfMSG, prefix)
        return None

    def firstRequest(self, message):
        if message['error'] != 'valid nickname':
            error = message['error']
            nickname = message['nickname']
            msgView = error
            self.writeInGlobalWindow('red', msgView, 'SERVER')
            msgView = "You new nickname: " + nickname
            self.writeInGlobalWindow('green', msgView, 'SERVER')
            self.lineEditNickName.setText(nickname)
        welcome = message['welcome']
        self.serverKey = message['PublicKeyServer']
        self.textEditPublicKeyServer.setText(self.serverKey)
        self.writeInGlobalWindow('green', welcome, 'SERVER')
        self.addItemsToWidget(message['rooms'])
        self.labelYourID.setText('your id: ' + message['id'])
        return None

    def resolutionAdmin(self, data):
        clientID = data['id']
        publicKeyClient = data['publicKey']
        self.clientKeys[int(clientID)] = publicKeyClient
        requests = data['requests']
        self.listWidgetRequests.clear()
        for i in requests:
            self.listWidgetRequests.addItem(str(i))
        prefix = "Room(" + self.roomNow + ")"
        msgView = "client " + clientID + " wants to connect to the room"
        self.writeInGlobalWindow('purple', msgView, prefix)
        return None

    def refreshRequests(self, data):
        requests = data['requests']
        self.listWidgetRequests.clear()
        for i in requests:
            self.listWidgetRequests.addItem(str(i))
        return None

    def invitationRoom(self, data):
        if data['error'] == 0:
            self.pushButtonExitRoom.setEnabled(True)
            self.pushButtonCreateRoom.setEnabled(False)
            self.lineEditNameNewRoom.setEnabled(False)
            self.pushButtonGenAES.setEnabled(False)
            nameRoom = data['name_room']
            self.roomNow = nameRoom
            welcome = data['welcome']
            prefix = "Room(" + self.roomNow + ")"
            self.writeInGlobalWindow('purple', welcome, prefix)
            cryptPrivateKeyRoom = bytes.fromhex(data['CryptPrivatKeyRoom'])
            privateKey = RSA.importKey(self.myKeysRSA['privateKey'])
            privateKeyRoom = privateKey.decrypt(cryptPrivateKeyRoom)

            self.roomKeyAES = privateKeyRoom
            self.textEditKeyRoomAES.setText(str(privateKeyRoom.hex()))
            self.labelNameRoom.setText('<html><head/><body><p align="center">' + nameRoom + '</p></body></html>')
        return None

    def errorCommand(self, data):
        typeError = str(data['type'])
        msg = str(data['error'])

        if typeError == 'exit':
            self.disconnectAlgorithm(typeError)
        elif typeError == 'try':
            self.writeInGlobalWindow('orange', msg, 'TRY')
        else:
            self.writeInGlobalWindow('red', msg, 'ERROR')
        return None
