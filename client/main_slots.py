from ui_main import Ui_MainWindow
from thread_work import WorkThread
from tab_page import TabPage
from PyQt5.QtWidgets import QWidget, QInputDialog, QDesktopWidget, QListWidgetItem
from PyQt5.QtGui import QColor, QTextCursor
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import random
import socket
import json


class MainWindowSlots(Ui_MainWindow):
    numerator = 0
    server = None
    serverKey = None
    tempPublicKey = None
    tempPrivateKey = None
    workThreadClient = None
    myKeysRSA = {'publicKey': None, 'privateKey': None}

    stackWidgetDict = {}
    publicKeysClients = {}
    notifMSG = {}
    tryCount = 0
    ID = None

    def showWidgetMyKeys(self):
        self.myKeysForm.show()

        if self.myKeysRSA['publicKey'] is not None and self.myKeysRSA['privateKey'] is not None:
            self.uiMyKeys.textEditMyPublicKeyRSA.setText(str(self.myKeysRSA['publicKey'].decode('utf-8')))
            self.uiMyKeys.textEditMyPrivatKeyRSA.setText(str(self.myKeysRSA['privateKey'].decode('utf-8')))
        if self.serverKey is not None:
            self.uiMyKeys.textEditPublicKeyServer.setText(str(self.serverKey))
        return None

    def showWidgetLog(self):
        self.logForm.show()
        self.tryCount = 0
        self.menuOptions.setTitle('Options')
        self.actionLog.setText('&Log')
        return None

    def showWidgetAbout(self):
        self.aboutForm.exec_()
        return None

    def buttonShowRandomGen(self):
        self.widgetGenRandom.show()
        return None

    def buttonSaveKeysRSA(self):
        if self.tempPublicKey is not None and self.tempPrivateKey is not None:
            self.myKeysRSA['publicKey'] = self.tempPublicKey
            self.myKeysRSA['privateKey'] = self.tempPrivateKey
            self.tempPublicKey = None
            self.tempPrivateKey = None
        self.myKeysForm.hide()
        return None

    def hideEventMyKeys(self, event):
        if event is None:
            return None
        self.tempPublicKey = None
        self.tempPrivateKey = None
        self.widgetGenRandom.hide()
        return None

    def eventGenRSA(self, event):
        if event is None:
            return None
        try:
            result = self.uiGenRandom.calculateRandomPointsArt()
            if result:
                self.tempPrivateKey, self.tempPublicKey = self.getNewKeysRSA()
                self.uiMyKeys.textEditMyPublicKeyRSA.setText(str(self.tempPublicKey.decode('utf-8')))
                self.uiMyKeys.textEditMyPrivatKeyRSA.setText(str(self.tempPrivateKey.decode('utf-8')))
                self.widgetGenRandom.hide()
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def getNewKeysRSA(self):
        try:
            bit = int(self.uiMyKeys.comboBoxBitRSA.currentText())
            randomBytes = self.uiGenRandom.randomGeneratorPointsArt(16)
            self.uiGenRandom.setRandomPointsArt(randomBytes)
            privateKey = RSA.generate(bit, self.uiGenRandom.randomGeneratorPointsArt)
            publicKey = privateKey.publickey()
            return privateKey.exportKey(), publicKey.exportKey()
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None, None

    def selectionChangedWidgetRooms(self):
        nameRoom = None
        try:
            if self.listWidgetRooms.currentItem().whatsThis() == 'room':
                nameRoom = self.listWidgetRooms.currentItem().toolTip()
                self.listWidgetRooms.currentItem().setText(nameRoom)
                self.listWidgetRooms.currentItem().setBackground(QColor(255, 255, 255))
                self.notifMSG[nameRoom] = 0
                if nameRoom in self.stackWidgetDict.keys():
                    index = self.stackWidgetDict[nameRoom]
                    self.stackedWidgetChats.setCurrentIndex(index)
                else:
                    index = self.addNewTab(nameRoom, 0, 1)
                    self.stackedWidgetChats.setCurrentIndex(index)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def addNewTab(self, nameRoom, acitve, encType):
        try:
            if nameRoom in self.stackWidgetDict.keys():
                index = self.stackWidgetDict[nameRoom]
                self.stackedWidgetChats.setCurrentIndex(index)
                self.stackedWidgetChats.widget(index).setActivateCodeRoom(acitve)
                self.stackedWidgetChats.setCurrentIndex(index)
                return index
            else:
                newStackWidget = TabPage(nameRoom, acitve, encType, self.stackedWidgetChats)
                newStackWidget.SendMsg.connect(self.sendMyMessage)
                newStackWidget.WidgetOnline.connect(self.workClientsFromWidgetOnline)
                newStackWidget.ExitRoom.connect(self.buttonExitRoom)
                newStackWidget.ErrorCommand.connect(self.errorCommand)
                newStackWidget.SendKeyRoom.connect(self.sendKeyRoom)
                index = self.stackedWidgetChats.addWidget(newStackWidget)
                self.stackWidgetDict[nameRoom] = index
                self.stackedWidgetChats.setCurrentIndex(index)
                return index
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)

    def buttonConnect(self):
        try:
            nickName = self.genNickname()
            self.lineEditNickName.setText(nickName)
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host = self.lineEditHost.text()
            port = self.lineEditPort.text()
            if self.firstConnect(host, port):
                self.refreshFormForConnect()
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def genNickname(self):
        nick = self.lineEditNickName.text()
        if nick == '':
            nick = 'nick' + str(random.randint(10000, 99999))
        return nick

    def firstConnect(self, host='127.0.0.1', portStr='8000'):
        self.myKeysRSA['privateKey'], self.myKeysRSA['publicKey'] = self.getNewKeysRSA()

        nickname = self.lineEditNickName.text()
        dataToSend = {'command': '-sFirstConnect', 'nickname': nickname,
                      'publicKey': self.myKeysRSA['publicKey'].decode('utf-8')}
        try:
            port = int(portStr)
            self.server.connect((host, port))
            self.workThreadClient = WorkThread(self.server, self.myKeysRSA['privateKey'])

            self.workThreadClient.replyServer.connect(self.comandsHandler)
            self.workThreadClient.start()
            self.writeInGlobalWindow('green', str(dataToSend), 'CLIENT', None, 1)
            message = json.dumps(dataToSend)
            self.server.send(bytes(message, "utf8"))
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return False
        return True

    def refreshFormForConnect(self):
        self.frameConnect.hide()
        self.listWidgetRooms.show()
        self.listWidgetRooms.show()
        self.frame.show()
        self.actionConnect.setEnabled(False)
        self.actionDisconnect.setEnabled(True)
        return None

    def buttonDisconnect(self):
        message = 'clicked buttonDisconnect. Disconnected from the server'
        self.disconnectAlgorithm(message)
        return None

    def disconnectAlgorithm(self, message):
        try:
            self.server.close()
            if not self.workThreadClient.wait(1):
                self.workThreadClient.terminate()
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        self.refreshFormForNoConnect()
        self.clearVarForNoConnect()
        message = message + '\n============DISCONNECT============='
        self.writeInGlobalWindow('red', message, 'DISCONNECT', None, 0)
        return None

    def refreshFormForNoConnect(self):
        try:
            self.frameConnect.show()
            self.listWidgetRooms.hide()
            self.listWidgetRooms.hide()
            self.frame.hide()
            self.actionConnect.setEnabled(True)
            self.actionDisconnect.setEnabled(False)
            self.listWidgetRooms.clear()
            for i in reversed(range(self.stackedWidgetChats.count())):
                widget = self.stackedWidgetChats.widget(i)
                self.stackedWidgetChats.removeWidget(widget)
                del widget
            self.labelYourID.setText('')
            self.uiMyKeys.textEditMyPublicKeyRSA.setText('')
            self.uiMyKeys.textEditMyPrivatKeyRSA.setText('')
            self.uiMyKeys.textEditPublicKeyServer.setText('')
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def clearVarForNoConnect(self):
        del self.workThreadClient
        del self.server
        self.serverKey = None
        self.tempPublicKey = None
        self.tempPrivateKey = None
        self.myKeysRSA = {'publicKey': None, 'privateKey': None}
        self.stackWidgetDict = {}
        self.publicKeysClients = {}
        self.notifMSG = {}
        self.ID = None

    def showWidgetRooms(self):
        if self.actionShow_Rooms.isChecked() and not self.actionConnect.isEnabled():
            self.listWidgetRooms.show()
            self.frame.show()
        else:
            self.listWidgetRooms.hide()
            self.frame.hide()
        return None

    def buttonExitRoom(self, nameRoom):
        dataToSend = {'command': '-sExitRoom', 'room': nameRoom}
        self.sendToServer(dataToSend)
        return None

    def sendKeyRoom(self, data):
        nameRoom = data['room']
        keyAES = data['keyAES']
        users = data['users']
        for usr in users:
            if int(usr) != self.ID:
                encryptKey = self.encryptDataRSA(keyAES, self.publicKeysClients[usr])
                dataToSend = {'command': '-sSetKeyAES',
                              'id': usr,
                              'encryptKeysAES': encryptKey,
                              'room': nameRoom}
                self.sendToServer(dataToSend)
        return None

    def workClientsFromWidgetOnline(self, data):
        nameRoom = None
        try:
            clientID = data['clientID']
            nameRoom = data['nameRoom']
            toolTip = data['toolTip']
            if clientID in self.publicKeysClients.keys():
                keyRSA = self.publicKeysClients[clientID]
                if toolTip == 'request':
                    keyRoom = data['keyRoom']
                    self.acceptRequestInRoom(clientID, nameRoom, keyRSA, keyRoom)
                elif toolTip == 'user':
                    dataToSend = {'command': '-sKickUser',
                                  'kick_id': clientID,
                                  'room': nameRoom}
                    self.sendToServer(dataToSend)
                else:
                    errorMsg = 'toolTip is :' + str(toolTip)
                    self.writeInGlobalWindow('red', errorMsg, 'ERROR', None, 0)
            else:
                self.getRSAKeyClient(clientID)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def getRSAKeyClient(self, clientID, nameRoom=None):
        dataToSend = {'command': '-sGetRSAKeyClient',
                      'user': clientID,
                      'room': nameRoom}
        self.sendToServer(dataToSend)
        return None

    def acceptRequestInRoom(self, clientID, nameRoom, publicKeyClient, keyRoom):
        try:
            cryptKeyAES = self.encryptDataRSA(keyRoom, publicKeyClient)
            dataToSend = {'command': '-sResolutionAdmin', 'response': 1,
                          'id': clientID, 'room': nameRoom,
                          'CryptPrivatKeyRoom': cryptKeyAES}
            self.sendToServer(dataToSend)
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def doubleClickedWidgetRooms(self):
        nameRoom = None
        try:
            if self.listWidgetRooms.currentItem().whatsThis() == 'create':
                self.createNewRoom()
            elif self.listWidgetRooms.currentItem().whatsThis() == 'room':
                nameRoom = self.listWidgetRooms.currentItem().toolTip()
                index = self.stackWidgetDict[nameRoom]
                activateCodeRoom = self.stackedWidgetChats.widget(index).getActivateCodeRoom()
                if activateCodeRoom == 0:
                    self.stackedWidgetChats.widget(index).setActivateCodeRoom(1)
                    dataToSend = {'command': '-sGo', 'room': str(nameRoom)}
                    self.sendToServer(dataToSend)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def createNewRoom(self):
        nameRoom = None
        try:
            dialog = QWidget()
            qr = dialog.frameGeometry()
            cp = QDesktopWidget().availableGeometry().center()
            qr.moveCenter(cp)
            dialog.move(qr.topLeft())
            nameRoom, ok = QInputDialog.getText(dialog, 'Create New Room', 'Enter room name:')
            if ok:
                dataToSend = {'command': '-sNewRoom', 'room': str(nameRoom)}
                self.sendToServer(dataToSend)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def sendMyMessage(self, data):
        nameRoom = None
        try:
            nameRoom = data['nameRoom']
            message = data['textMSG']
            encrypt = data['encrypt']
            dataToSend = {'command': '-sMsg', 'message': message,
                          'room': nameRoom, 'encrypt': encrypt}
            self.sendToServer(dataToSend)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def encryptDataRSA(self, text, key):
        try:
            publicKey = RSA.importKey(bytes(key, "utf8"))
            cipherRSA = PKCS1_OAEP.new(publicKey)

            sessionKey = self.uiGenRandom.randomGeneratorPointsArt(16)
            encSessionKey = cipherRSA.encrypt(sessionKey)

            cipherAES = AES.new(sessionKey, AES.MODE_EAX)
            cipherText, tag = cipherAES.encrypt_and_digest(text.encode('utf-8'))

            packet = [encSessionKey.hex(),
                      cipherAES.nonce.hex(),
                      cipherText.hex(),
                      tag.hex()]
            packetDumps = json.dumps(packet)
            return packetDumps
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return None

    def decryptDataRSA(self, encryptData, key=None):
        try:
            if key is None:
                key = self.myKeysRSA['privateKey']
            encryptList = json.loads(encryptData)

            encSessionKey = bytes.fromhex(encryptList[0])
            nonce = bytes.fromhex(encryptList[1])
            cipherText = bytes.fromhex(encryptList[2])
            tag = bytes.fromhex(encryptList[3])

            myCipherRSA = PKCS1_OAEP.new(RSA.importKey(key))
            sessionKey = myCipherRSA.decrypt(encSessionKey)
            cipherAES = AES.new(sessionKey, AES.MODE_EAX, nonce)
            dataDump = cipherAES.decrypt_and_verify(cipherText, tag)
            return dataDump.decode('utf-8')
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return None

    def sendToServer(self, message):
        import time
        try:
            self.writeInGlobalWindow('green', str(message), 'CLIENT', None, 1)
            messageJson = json.dumps(message)
            packet = self.encryptDataRSA(messageJson, self.serverKey)
            if len(packet) < 4096:
                time.sleep(0.01)
                self.server.send(packet.encode('utf-8') + b'+')
            else:
                errorMsg = 'sendToServer. error: len command have big size'
                self.writeInGlobalWindow('red', errorMsg, 'ERROR', None, 0)
                return False
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return False
        return True

    def writeInGlobalWindow(self, color, text, prefix, nameRoom, address):
        import datetime
        try:
            timeChat = datetime.datetime.today().strftime("%H:%M:%S")
            timeChat = '<font color=\"black\">[' + timeChat + ']</font>'
            if address == 0 or address is None:
                textToWindowChat = "<font color=\"" + color + "\">" + \
                                   timeChat + prefix + '[' + str(nameRoom) + ']: '\
                                   + str(text) + "</font><br>"
                cursor = self.uiLog.textEditMainLog.textCursor()
                cursor.movePosition(QTextCursor.End)
                self.uiLog.textEditMainLog.setTextCursor(cursor)
                self.uiLog.textEditMainLog.insertHtml(textToWindowChat)
                cursor = self.uiLog.textEditMainLog.textCursor()
                self.uiLog.textEditMainLog.setTextCursor(cursor)
                if color == 'orange' and not self.logForm.isVisible():
                    self.tryCount += 1
                    self.menuOptions.setTitle('Options +' + str(self.tryCount))
                    self.actionLog.setText('&Log +' + str(self.tryCount))
            elif address == 1:
                textToWindowChat = "<font color=\"" + color + "\">" + \
                                   timeChat + prefix + ": " + str(text) + "</font><br>"
                cursor = self.uiLog.textEditRequestsLog.textCursor()
                cursor.movePosition(QTextCursor.End)
                self.uiLog.textEditRequestsLog.setTextCursor(cursor)
                self.uiLog.textEditRequestsLog.insertHtml(textToWindowChat)
                cursor = self.uiLog.textEditRequestsLog.textCursor()
                self.uiLog.textEditRequestsLog.setTextCursor(cursor)
            else:
                textToWindowChat = "<font color=\"" + color + "\">" + \
                                   timeChat + prefix + '[' + str(address) + ']: ' \
                                   + str(text) + "</font><br>"
                index = self.stackWidgetDict[address]
                self.stackedWidgetChats.widget(index).writeTextInWindowChat(textToWindowChat)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def comandsHandler(self, data):
        try:
            command = data['command']
            if command == '-sFirstRequest':
                self.firstRequest(data)
            elif command == '-sRooms':
                self.refreshRoomsWidget(data['rooms'])
            elif command == '-sSetRoomRight':
                self.setRoomRight(data)
            elif command == '-sRefreshUsers':
                self.refreshOnlineWidget(data)
            elif command == '-sNewRoom':
                self.responseCreateNewRoom(data)
            elif command == '-sMsg':
                self.acceptMessage(data)
            elif command == '-sSetKeyAES':
                self.setKeyAES(data)
            elif command == '-sSetRSAKeyClient':
                self.setRSAKeyClient(data)
            elif command == '-sError':
                self.errorCommand(data)
            else:
                self.writeInGlobalWindow('red', str(data), 'ERROR COMMAND', None, 1)
                return None
            self.writeInGlobalWindow('black', str(data), 'SERVER', None, 1)
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return None
        return None

    def firstRequest(self, data):
        try:
            nameRoom = data['room']
            error = data['error']
            if error != 'valid nickname':
                nickname = data['nickname']
                self.writeInGlobalWindow('red', error, 'SERVER', nameRoom, nameRoom)
                msgView = "You new nickname: " + nickname
                self.writeInGlobalWindow('green', msgView, 'SERVER', nameRoom, nameRoom)
                self.lineEditNickName.setText(nickname)
            self.ID = int(data['id'])
            self.addNewTab(nameRoom, 2, 0)
            welcome = data['welcome']
            self.serverKey = data['PublicKeyServer']
            self.uiMyKeys.textEditPublicKeyServer.setText(self.serverKey)
            self.writeInGlobalWindow('green', welcome, 'SERVER', nameRoom, nameRoom)
            self.refreshRoomsWidget(data['rooms'])
            self.labelYourID.setText('Your ID: ' + data['id'])
            welcome = welcome + '\n=============CONNECT==============='
            self.writeInGlobalWindow('green', welcome, 'CONNECT', None, 0)
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def refreshRoomsWidget(self, items):
        try:
            self.listWidgetRooms.clear()
            itemWidget = QListWidgetItem("create new room")
            itemWidget.setBackground(QColor(142, 255, 203))
            itemWidget.setToolTip('system item')
            itemWidget.setWhatsThis("create")
            self.listWidgetRooms.addItem(itemWidget)
            items.sort()
            for item in items:
                self.notifMSG[item] = 0
                iWidget = QListWidgetItem(item)
                iWidget.setWhatsThis("room")
                iWidget.setToolTip(item)
                self.listWidgetRooms.addItem(iWidget)
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def setRoomRight(self, data):   # -sSetRoomRight
        nameRoom = None
        try:
            nameRoom = data['room']
            roomRight = data['right']
            msgView = data['welcome']
            color = data['color']
            index = self.stackWidgetDict[nameRoom]
            #   if roomRight == 0:
            #   elif roomRight == 1:
            if roomRight == 2 and data['CryptPrivatKeyRoom'] is not None:
                cryptPrivateKeyRoom = data['CryptPrivatKeyRoom']
                privateKeyRoom = self.decryptDataRSA(cryptPrivateKeyRoom)
                self.stackedWidgetChats.widget(index).setKeyRoomAES(privateKeyRoom)
            #   elif roomRight == 3:
            self.writeInGlobalWindow(color, msgView, 'SERVER', nameRoom, nameRoom)
            self.stackedWidgetChats.widget(index).setActivateCodeRoom(roomRight)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def refreshOnlineWidget(self, data):
        nameRoom = None
        try:
            nameRoom = data['room']
            admin = data['admin']
            users = data['users']
            requests = data['requests']
            index = self.stackWidgetDict[nameRoom]

            self.stackedWidgetChats.widget(index).refreshOnlineListinTab(
                admin, users, requests)
            if admin is not None:
                if admin in self.publicKeysClients.keys():
                    self.stackedWidgetChats.widget(index).writeInClientKeysRSA(
                        admin, self.publicKeysClients[admin], 'red')
                else:
                    self.getRSAKeyClient(admin)
            for usr in users:
                if usr in self.publicKeysClients.keys():
                    self.stackedWidgetChats.widget(index).writeInClientKeysRSA(
                        usr, self.publicKeysClients[usr], 'green')
                else:
                    self.getRSAKeyClient(usr)
            for req in requests:
                if req in self.publicKeysClients.keys():
                    self.stackedWidgetChats.widget(index).writeInClientKeysRSA(
                        req, self.publicKeysClients[req], 'purple')
                else:
                    self.getRSAKeyClient(req)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def responseCreateNewRoom(self, data):
        nameRoom = None
        try:
            nameRoom = data['room']
            self.addNewTab(nameRoom, 3, 1)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def acceptMessage(self, data):
        nameRoom = None
        try:
            nameRoom = data['room']
            nick = data['nickname']
            clientID = str(data['id'])
            prefix = '<font color=\"grey\">' + nick + '(' + clientID + ')</font>'
            index = self.stackWidgetDict[nameRoom]
            self.stackedWidgetChats.widget(index).writeMSG(data['message'], prefix, True)
            if index != self.stackedWidgetChats.currentIndex():
                for item in range(self.listWidgetRooms.count()):
                    if nameRoom == self.listWidgetRooms.item(item).toolTip():
                        self.notifMSG[nameRoom] += 1
                        self.listWidgetRooms.item(item).setBackground(QColor(255, 220, 102))
                        self.listWidgetRooms.item(item).setText(
                            '+' + str(self.notifMSG[nameRoom]) + ' ' + nameRoom)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def setKeyAES(self, data):
        nameRoom = None
        try:
            nameRoom = data['room']
            encryptKeysAES = data['encryptKeysAES']
            keyAES = self.decryptDataRSA(encryptKeysAES)
            index = self.stackWidgetDict[nameRoom]
            self.stackedWidgetChats.widget(index).setKeyRoomAES(keyAES)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def setRSAKeyClient(self, data):
        try:
            user = data['user']
            keyRSA = data['keyRSA']
            self.publicKeysClients[user] = keyRSA
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def errorCommand(self, data):
        nameRoom = None
        try:
            typeError = str(data['type'])
            msg = str(data['text'])
            nameRoom = data['room']
            address = data['address']
            if typeError == 'exit':
                self.disconnectAlgorithm(msg)
            elif typeError == 'orange':
                self.writeInGlobalWindow('orange', msg, 'TRY', nameRoom, address)
            elif typeError == 'purple':
                self.writeInGlobalWindow('purple', msg, 'SERVER(room)', nameRoom, address)
            elif typeError == 'red':
                self.writeInGlobalWindow('red', msg, 'SERVER', nameRoom, address)
            else:
                self.writeInGlobalWindow('red', msg, 'UnknownServerError', nameRoom, address)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def excaptionWrite(self, errorTry, nameRoom=None):
        import inspect
        nameFun = inspect.stack()[1][3]
        errorMsg = 'nameFun: ' + str(nameFun) + '. TRY: ' + str(errorTry)
        self.writeInGlobalWindow('orange', errorMsg, 'TRY', nameRoom, 0)
        return None
