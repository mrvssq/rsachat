from ui_main import Ui_MainWindow
from thread_work import WorkThread
from tab_page import TabPage
from PyQt5.QtWidgets import QWidget, QInputDialog, QDesktopWidget, QListWidgetItem
from PyQt5.QtGui import QColor, QTextCursor
from Crypto.PublicKey import RSA
from Crypto.Random import random
import socket
import json


class MainWindowSlots(Ui_MainWindow):
    server = None
    myKeysRSA = {'publicKey': None, 'privateKey': None}
    serverKey = None
    stackWidgetDict = {}

    tempPublicKey = None
    tempPrivateKey = None

    def showWidgetMyKeys(self):
        self.myKeysForm.show()

        if self.myKeysRSA['publicKey'] is not None\
            and self.myKeysRSA['privateKey'] is not None\
                and self.serverKey is not None:
            self.uiMyKeys.textEditMyPublicKeyRSA.setText(str(self.myKeysRSA['publicKey'].decode('utf-8')))
            self.uiMyKeys.textEditMyPrivatKeyRSA.setText(str(self.myKeysRSA['privateKey'].decode('utf-8')))
            self.uiMyKeys.textEditPublicKeyServer.setText(str(self.serverKey))
        return None

    def showWidgetLog(self):
        self.logForm.show()
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

    def genRSA(self, event=None):
        try:
            bit = int(self.uiMyKeys.comboBoxBitRSA.currentText())
            result = self.uiGenRandom.calculateRandomPointsArt()
            randomBytes = self.uiGenRandom.randomGeneratorPointsArt(10)
            self.uiGenRandom.setRandomPointsArt(randomBytes)
            privateKey = RSA.generate(bit, self.uiGenRandom.randomGeneratorPointsArt)
            publicKey = privateKey.publickey()
            if event is None:
                self.myKeysRSA['publicKey'] = publicKey.exportKey()
                self.myKeysRSA['privateKey'] = privateKey.exportKey()
                return None
            elif result:
                self.tempPublicKey = publicKey.exportKey()
                self.tempPrivateKey = privateKey.exportKey()
                self.uiMyKeys.textEditMyPublicKeyRSA.setText(str(self.tempPublicKey.decode('utf-8')))
                self.uiMyKeys.textEditMyPrivatKeyRSA.setText(str(self.tempPrivateKey.decode('utf-8')))
                self.widgetGenRandom.hide()
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def clickedDisplayWidgetRooms(self):
        nameRoom = None
        try:
            if self.listWidgetRooms.currentItem().toolTip() == 'room':
                nameRoom = self.listWidgetRooms.currentItem().text()
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
        self.genRSA()
        nickname = self.lineEditNickName.text()
        dataToSend = {'command': '-sFirstConnect', 'nickname': nickname,
                      'publicKey': self.myKeysRSA['publicKey'].decode('utf-8')}
        try:
            port = int(portStr)
            self.server.connect((host, port))
            self.workThreadClient = WorkThread(self.server, self.myKeysRSA['privateKey'].decode('utf-8'))
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
                print('workThreadClient.terminate()')
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
        self.server = None
        self.myKeysRSA = {'publicKey': None, 'privateKey': None}
        self.serverKey = None
        self.stackWidgetDict = {}

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
        key = data['keyAES']
        dataToSend = {'command': '-sSetKeyAES', 'keyAES': key, 'room': nameRoom}
        self.sendToServer(dataToSend)
        return None

    def workClientsFromWidgetOnline(self, data):
        nameRoom = None
        try:
            clientID = data['clientID']
            nameRoom = data['nameRoom']
            toolTip = data['toolTip']
            if toolTip == 'request':
                self.acceptRequestInRoom(clientID, nameRoom, data['keyClient'])
            elif toolTip == 'user':
                dataToSend = {'command': '-sKickUser', 'kick_id': clientID, 'room': nameRoom}
                self.sendToServer(dataToSend)
            else:
                print('toolTip is :' + toolTip)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
        return None

    def acceptRequestInRoom(self, clientID, nameRoom, publicKeyClient):
        try:
            pubKeyBytesRSA = bytes(str(publicKeyClient), "utf8")
            rightKeyPublicClient = RSA.importKey(pubKeyBytesRSA)
            index = self.stackWidgetDict[nameRoom]
            roomKey = self.stackedWidgetChats.widget(index).getKeyRoomAES()
            cryptAES256 = rightKeyPublicClient.encrypt(roomKey, self.uiGenRandom.randomGeneratorPointsArt)
            dataToSend = {'command': '-sResolutionAdmin', 'response': 1, 'id': clientID, 'room': nameRoom,
                          'cryptPrivatkey': str(cryptAES256[0].hex())}
            self.sendToServer(dataToSend)
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def doubleClickedWidgetRooms(self):
        nameRoom = None
        try:
            if self.listWidgetRooms.currentItem().toolTip() == 'create':
                self.createNewRoom()
            elif self.listWidgetRooms.currentItem().toolTip() == 'room':
                nameRoom = self.listWidgetRooms.currentItem().text()
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
            dataToSend = {'command': '-sMsg', 'message': message, 'room': nameRoom}
            self.sendToServer(dataToSend)
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
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
                    message = key.encrypt(bytes(enterMSG, "utf8"), self.uiGenRandom.randomGeneratorPointsArt)
                    sendMSG += message[0] + b'--[SPLIT]--'
                    messageJson = messageJson[250:]
                    i += 1
            message = key.encrypt(bytes(messageJson, "utf8"), self.uiGenRandom.randomGeneratorPointsArt)
            sendMSG += message[0] + b'--[SPLIT]--}end}'
            return sendMSG
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return 'error cryptoForServerRSA'

    def sendToServer(self, message):
        try:
            self.writeInGlobalWindow('green', str(message), 'CLIENT', None, 1)
            messageJson = json.dumps(message)
            sendMSG = self.cryptoForServerRSA(messageJson)
            if len(sendMSG) < 4096:
                self.server.send(sendMSG)
            else:
                errorMsg = 'send_to_server. error: len command have big size'
                self.writeInGlobalWindow('red', errorMsg, 'ERROR', None, 0)
                return False
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return False

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
            itemWidget.setToolTip("create")
            self.listWidgetRooms.addItem(itemWidget)
            items.sort()
            for item in items:
                iWidget = QListWidgetItem(item)
                iWidget.setToolTip("room")
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
                cryptPrivateKeyRoom = bytes.fromhex(data['CryptPrivatKeyRoom'])
                privateKey = RSA.importKey(self.myKeysRSA['privateKey'])
                privateKeyRoom = privateKey.decrypt(cryptPrivateKeyRoom)
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
            index = self.stackWidgetDict[nameRoom]
            self.stackedWidgetChats.widget(index).refreshOnlineListinTab(
                str(data['admin']), data['users'], data['requests'])
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
        except Exception as errorTry:
            self.excaptionWrite(errorTry, nameRoom)
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
