from ui_widget_template_chat import Ui_FormTemplateChat
from ui_dialog_settings_room import Ui_DialogSettingsRoom
from gen_random_slots import GenRandomSlots
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import pyqtSignal, QRect
from PyQt5.QtGui import QTextCursor, QColor
from PyQt5.QtWidgets import QDialog, QWidget
from Crypto.Cipher import AES
import datetime
import json


class TabPage(QtWidgets.QWidget):
    SendMsg = pyqtSignal(dict)
    WidgetOnline = pyqtSignal(dict)
    ExitRoom = pyqtSignal(str)
    ErrorCommand = pyqtSignal(dict)
    SendKeyRoom = pyqtSignal(dict)

    def __init__(self, nameRoom, active, encryptionType, parent=None, key=None):
        super().__init__(parent)
        self.nameRoom = nameRoom
        self.activateState = active
        self.keyRoomAES = [key]
        self.tempKeyAES = None
        self.encryptionType = encryptionType
        self.clients = []
        self.requests = []

        self.WidgetChat = QWidget(self)
        self.resizeEvent = self.resizeEventGridLayout
        self.uiChat = Ui_FormTemplateChat()
        self.keyPressEventOldMessage = None
        self.createWidgetChatSlots()

        self.SettingsDlg = QDialog()
        self.uiSettings = Ui_DialogSettingsRoom()
        self.createSettingsRoomSlots()

        self.widgetGenRandom = QWidget(self.SettingsDlg)
        self.uiGenRandom = GenRandomSlots(self.widgetGenRandom)
        self.createWidgetGenRandomSlots()

        self.setActivateCodeRoom(self.activateState)
        self.setForm()

    def setForm(self):
        self.uiChat.splitter1.setStretchFactor(0, 5)
        self.uiChat.splitter1.setStretchFactor(1, 1)
        self.uiChat.splitter2.setStretchFactor(0, 4)
        self.uiChat.splitter2.setStretchFactor(1, 1)
        self.uiChat.nameRoomLabel.setText(self.nameRoom)
        self.widgetGenRandom.hide()
        self.widgetGenRandom.setGeometry(QRect(243, 80, 250, 130))
        self.widgetGenRandom.setMinimumSize(250, 130)
        self.widgetGenRandom.setMaximumSize(250, 130)

    def createWidgetChatSlots(self):
        self.uiChat.setupUi(self.WidgetChat)
        self.keyPressEventOldMessage = self.uiChat.lineEditSendMsg.keyPressEvent
        self.uiChat.lineEditSendMsg.keyPressEvent = self.buttonSendEnterMSG
        self.uiChat.listWidgetOnline.itemDoubleClicked.connect(self.doubleClickedWidgetOnline)
        self.uiChat.pushButtonShowOnline.clicked.connect(self.buttonShowOnline)
        self.uiChat.pushButtonExitRoom.clicked.connect(self.buttonExitRoom)
        self.uiChat.pushButtonSettings.clicked.connect(self.showSettingsRoom)

    def createSettingsRoomSlots(self):
        self.uiSettings.setupUi(self.SettingsDlg)
        self.uiSettings.pushButtonGenAES.clicked.connect(self.buttonGenKeyAES)
        self.uiSettings.pushButtonSave.clicked.connect(self.buttonSaveKeysAES)
        self.SettingsDlg.showEvent = self.showEventSettingsDlg
        self.SettingsDlg.hideEvent = self.hideEventSettingsDlg

    def createWidgetGenRandomSlots(self):
        self.uiGenRandom.setupUi(self.widgetGenRandom)
        self.widgetGenRandom.mouseReleaseEvent = self.genAES

    def showEventSettingsDlg(self, event):
        if event is None:
            return None
        if self.activateState == 2 or self.activateState == 3:
            key = 'error key'
            if self.encryptionType == 1:
                if self.keyRoomAES[-1] is not None:
                    key = str(self.keyRoomAES[-1].hex())
            if self.encryptionType == 0:
                key = 'no encryption'
            self.uiSettings.textEditKeyRoomAES.setText(key)
        return None

    def hideEventSettingsDlg(self, event):
        if event is None:
            return None
        self.tempKeyAES = None
        self.widgetGenRandom.hide()

    def buttonSaveKeysAES(self):
        if self.tempKeyAES is not None:
            if self.activateState == 3:
                self.keyRoomAES.append(self.tempKeyAES)
                dataSend = {'keyAES': self.tempKeyAES.hex(),
                            'room': self.nameRoom,
                            'users': self.clients}
                self.SendKeyRoom.emit(dataSend)
                self.writeNotice('Room key AES256 changed', 'SERVER')
            self.tempKeyAES = None
        self.SettingsDlg.hide()

    def genAES(self, event=None):
        import hashlib
        try:
            result = self.uiGenRandom.calculateRandomPointsArt()
            randomSHA256 = self.uiGenRandom.randomGeneratorPointsArt(512)
            keyAES256 = hashlib.sha256(randomSHA256).digest()
            if event is None:
                if self.keyRoomAES[-1] is None:
                    self.keyRoomAES.append(keyAES256)
            else:
                if result:
                    self.tempKeyAES = keyAES256
                    self.uiSettings.textEditKeyRoomAES.setText(keyAES256.hex())
                    self.widgetGenRandom.hide()
        except Exception as errorTry:
            self.exceptionWrite(errorTry)
        return None

    def resizeEventGridLayout(self, event):
        w = event.size().width()
        h = event.size().height()
        self.WidgetChat.setGeometry(QRect(0, 0, w, h))
        self.uiChat.layoutWidget.setGeometry(QRect(0, 0, w, h))

    def setActivateCodeRoom(self, code):
        self.activateState = code
        if code == 0:
            self.uiChat.indicatorLabel.setText("offline")
            self.uiChat.indicatorLabel.setStyleSheet("color: rgb(255, 255, 255);"
                                                     "font: 75 10pt \"Noto Sans\";"
                                                     "background-color: rgb(166, 166, 166);")
            self.uiChat.listWidgetOnline.clear()
            self.uiChat.listWidgetOnline.hide()
            self.uiChat.pushButtonExitRoom.setEnabled(False)
            self.uiChat.pushButtonExitRoom.setText('Exit Room')
            self.uiSettings.textEditKeyRoomAES.setText('')
            self.uiSettings.textEditPublicKeysClients.setText('')
            self.clients.clear()
            self.requests.clear()
        elif code == 1:
            self.uiChat.indicatorLabel.setText("request")
            self.uiChat.indicatorLabel.setStyleSheet("color: rgb(255, 255, 255);"
                                                     "font: 75 10pt \"Noto Sans\";"
                                                     "background-color: rgb(214, 142, 255);")
            self.uiChat.listWidgetOnline.clear()
            self.uiChat.listWidgetOnline.hide()
            self.uiChat.pushButtonExitRoom.setEnabled(True)
            self.uiChat.pushButtonExitRoom.setText('Cancel')
            self.uiSettings.textEditKeyRoomAES.setText('')
            self.uiSettings.textEditPublicKeysClients.setText('')
            self.clients.clear()
            self.requests.clear()
        elif code == 2:
            self.uiChat.indicatorLabel.setText("user")
            self.uiChat.indicatorLabel.setStyleSheet("color: rgb(255, 255, 255);"
                                                     "font: 75 10pt \"Noto Sans\";"
                                                     "background-color: rgb(58, 197, 116);")
            self.uiChat.listWidgetOnline.show()
            self.uiChat.pushButtonExitRoom.setEnabled(True)
            self.uiChat.pushButtonExitRoom.setText('Exit Room')
        elif code == 3:
            self.uiChat.indicatorLabel.setText("admin")
            self.uiChat.indicatorLabel.setStyleSheet("color: rgb(255, 255, 255);"
                                                     "font: 75 10pt \"Noto Sans\";"
                                                     "background-color: rgb(255, 107, 109);")
            self.uiChat.listWidgetOnline.show()
            self.uiChat.pushButtonExitRoom.setEnabled(True)
            self.uiChat.pushButtonExitRoom.setText('Exit Room')
            self.genAES()
        return None

    def buttonExitRoom(self):
        self.ExitRoom.emit(self.nameRoom)

    def buttonGenKeyAES(self):
        if self.encryptionType == 1 and self.activateState != 2:
            self.widgetGenRandom.show()

    def showSettingsRoom(self):
        self.SettingsDlg.exec_()

    def buttonShowOnline(self):
        if self.uiChat.listWidgetOnline.isVisible():
            self.uiChat.listWidgetOnline.hide()
            self.uiChat.pushButtonShowOnline.setText('<')
        else:
            self.uiChat.listWidgetOnline.show()
            self.uiChat.pushButtonShowOnline.setText('>')

    def buttonSendEnterMSG(self, event):
        try:
            if event.key() == QtCore.Qt.Key_Return:
                textMSG = self.uiChat.lineEditSendMsg.toPlainText()
                if textMSG != '' and self.activateState != 0 and self.activateState != 1:
                    self.sentMsgToServer(textMSG.replace('\n', '<br>'))
            else:
                self.keyPressEventOldMessage(event)
        except Exception as errorTry:
            self.exceptionWrite(errorTry)
        return None

    def sentMsgToServer(self, textMSG):
        import textwrap
        import time
        lengthMSG = 500
        try:
            blocksMSG = textwrap.wrap(textMSG, lengthMSG)
            for message in blocksMSG:
                if len(blocksMSG) >= 3:
                    time.sleep(1)
                encryptMsg = self.encryptTextToAES(message)
                msgDict = {'nameRoom': self.nameRoom, 'textMSG': encryptMsg}
                self.writeMSG(message, "<font color=\"blue\">You</font>", False)
                self.SendMsg.emit(msgDict)
            self.uiChat.lineEditSendMsg.setPlainText('')
        except Exception as errorTry:
            self.exceptionWrite(errorTry)
        return None

    def doubleClickedWidgetOnline(self):
        try:
            clientID = self.uiChat.listWidgetOnline.currentItem().text()
            toolTip = self.uiChat.listWidgetOnline.currentItem().toolTip()
            if toolTip != 'admin' and self.activateState == 3:
                sendDict = {'nameRoom': self.nameRoom,
                            'clientID': int(clientID),
                            'toolTip': toolTip,
                            'keyRoom': self.keyRoomAES[-1].hex()}
                self.WidgetOnline.emit(sendDict)
        except Exception as errorTry:
            self.exceptionWrite(errorTry)
        return None

    def writeInClientKeysRSA(self, clientID, publicKeyClient, color):
        self.uiSettings.textEditPublicKeysClients.insertHtml("<font color=\"" + color + "\">Public_Key client "
                                                             + str(clientID) + ":<br>" + str(publicKeyClient)
                                                             + "</font><br>")
        self.uiSettings.textEditPublicKeysClients.insertHtml(
            "<font color=\"black\">=============================</font><br>")

    def refreshOnlineListinTab(self, admin, users, requests):
        try:
            self.uiChat.listWidgetOnline.clear()
            self.uiSettings.textEditPublicKeysClients.clear()
            self.clients.clear()
            self.requests.clear()
            if admin in users:
                users.remove(admin)
                itemWidget = QtWidgets.QListWidgetItem(str(admin))
                itemWidget.setBackground(QColor(255, 142, 142))
                itemWidget.setToolTip("admin")
                self.uiChat.listWidgetOnline.addItem(itemWidget)
                self.clients.append(admin)
            for item in users:
                itemWidget = QtWidgets.QListWidgetItem(str(item))
                itemWidget.setBackground(QColor(142, 255, 203))
                itemWidget.setToolTip("user")
                self.uiChat.listWidgetOnline.addItem(itemWidget)
                self.clients.append(item)
            for item in requests:
                itemWidget = QtWidgets.QListWidgetItem(str(item))
                itemWidget.setBackground(QColor(214, 142, 255))
                itemWidget.setToolTip("request")
                self.uiChat.listWidgetOnline.addItem(itemWidget)
                self.requests.append(item)
        except Exception as errorTry:
            self.exceptionWrite(errorTry)
        return None

    def writeMSG(self, message, prefix, encrypt):
        try:
            timeChat = datetime.datetime.today().strftime("%H:%M:%S")
            timeChat = '<font color=\"black\">[' + timeChat + ']</font>'
            if encrypt:
                message = self.decryptTextFromAES(message)
            textToWindowChat = "<font color=\"black\">" + \
                               timeChat + prefix + ": " + message + "</font><br>"
            self.writeTextInWindowChat(textToWindowChat)
        except Exception as errorTry:
            self.exceptionWrite(errorTry)
        return None

    def writeNotice(self, message, prefix):
        try:
            timeChat = datetime.datetime.today().strftime("%H:%M:%S")
            timeChat = '<font color=\"black\">[' + timeChat + ']</font>'
            textToWindowChat = "<font color=\"purple\">" + \
                               timeChat + prefix + ": " + message + "</font><br>"
            self.writeTextInWindowChat(textToWindowChat)
        except Exception as errorTry:
            self.exceptionWrite(errorTry)
        return None

    def writeTextInWindowChat(self, text):
        cursor = self.uiChat.textEditGlobal.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.uiChat.textEditGlobal.setTextCursor(cursor)
        self.uiChat.textEditGlobal.insertHtml(str(text))
        cursor = self.uiChat.textEditGlobal.textCursor()
        self.uiChat.textEditGlobal.setTextCursor(cursor)

    def encryptTextToAES(self, message):
        try:
            key256 = self.keyRoomAES[-1]
            if key256 is None:
                return message
            else:
                cipher = AES.new(key256, AES.MODE_EAX)
                cipherText, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
                enc = [cipherText.hex(), cipher.nonce.hex(), tag.hex()]
                jsonDumps = json.dumps(enc)
                return jsonDumps
        except Exception as errorTry:
            self.exceptionWrite(errorTry)
            return None

    def decryptTextFromAES(self, jsonDumps):
        try:
            key256 = self.keyRoomAES[-1]
            if key256 is None:
                message = jsonDumps
            else:
                data = json.loads(jsonDumps)

                cipherText = bytes.fromhex(data[0])
                nonce = bytes.fromhex(data[1])
                tag = bytes.fromhex(data[2])

                cipher = AES.new(key256, AES.MODE_EAX, nonce)
                message = cipher.decrypt_and_verify(cipherText, tag).decode('utf-8')
            return message
        except Exception as errorTry:
            self.exceptionWrite(errorTry)
            return None

    def getActivateCodeRoom(self):
        return self.activateState

    def setKeyRoomAES(self, key):
        keyBytes = bytes.fromhex(key)
        if self.keyRoomAES[-1] is not None and self.keyRoomAES[-1] != keyBytes:
            self.writeNotice('Room key AES256 changed', 'SERVER')
        self.keyRoomAES.append(keyBytes)
        self.uiSettings.textEditKeyRoomAES.setText(key)
        return None

    def getKeyRoomAES(self):
        return self.keyRoomAES[-1].hex()

    def exceptionWrite(self, errorTry):
        import inspect
        nameFun = inspect.stack()[1][3]
        errorMsg = 'nameFun: ' + str(nameFun) + '. TRY: ' + str(errorTry)
        errorSend = {'command': '-sError', 'type': 'orange',
                     'text': errorMsg, 'room': self.nameRoom, 'address': None}
        self.ErrorCommand.emit(errorSend)
        return None
