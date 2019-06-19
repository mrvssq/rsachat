from ui_widget_template_chat import Ui_FormTemplateChat
from ui_dialog_settings_room import Ui_DialogSettingsRoom
from gen_random_slots import GenRandomSlots
from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import pyqtSignal, QRect
from PyQt5.QtGui import QTextCursor, QColor
from PyQt5.QtWidgets import QDialog, QWidget
from Crypto.Cipher import AES
from Crypto import Random
import base64


class TabPage(QtWidgets.QWidget):
    SendMsg = pyqtSignal(dict)
    WidgetOnline = pyqtSignal(dict)
    ExitRoom = pyqtSignal(str)
    ErrorCommand = pyqtSignal(dict)

    def __init__(self, nameRoom, active, encryptionType, parent=None, key=None):
        super().__init__(parent)
        self.nameRoom = nameRoom
        self.activateState = active
        self.keyRoomAES = [key]
        self.tempKeyAES = None
        self.currentCountKey = 0
        self.encryptionType = encryptionType
        self.clientKeys = []

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
        key = 'error key'
        if self.encryptionType == 1:
            if self.keyRoomAES[self.currentCountKey] is not None:
                key = str(self.keyRoomAES[self.currentCountKey].hex())
        if self.encryptionType == 0:
            key = 'no encryption'
        self.uiSettings.textEditKeyRoomAES.setText(key)

    def hideEventSettingsDlg(self, event):
        if event is None:
            return None
        self.tempKeyAES = None
        self.widgetGenRandom.hide()

    def buttonSaveKeysAES(self):
        if self.tempKeyAES is not None:
            self.keyRoomAES.append(self.tempKeyAES)
            self.currentCountKey = self.currentCountKey + 1
            self.tempKeyAES = None
        self.SettingsDlg.hide()

    def genAES(self, event=None):
        import hashlib
        try:
            result = self.uiGenRandom.calculateRandomPointsArt()
            randomSHA256 = self.uiGenRandom.randomGeneratorPointsArt(512)
            keyAES256 = hashlib.sha256(randomSHA256).digest()
            if event is None:
                if self.keyRoomAES[self.currentCountKey] is None:
                    self.keyRoomAES.append(keyAES256)
                    self.currentCountKey = self.currentCountKey + 1
            else:
                if result:
                    self.tempKeyAES = keyAES256
                    self.uiSettings.textEditKeyRoomAES.setText(str(keyAES256.hex()))
                    self.widgetGenRandom.hide()
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
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
            self.excaptionWrite(errorTry)
        return None

    def sentMsgToServer(self, textMSG):
        import time
        import textwrap
        lengthMSG = 2000
        try:
            blocksMSG = textwrap.wrap(textMSG, lengthMSG)
            for message in blocksMSG:
                if len(blocksMSG) >= 3:
                    time.sleep(10)
                encryptMsg = self.encryptTextToAES(message)
                msgDict = {'nameRoom': self.nameRoom, 'textMSG': encryptMsg}
                self.writeMSG(message, "<font color=\"blue\">You</font>", False)
                self.SendMsg.emit(msgDict)
            self.uiChat.lineEditSendMsg.setPlainText('')
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def doubleClickedWidgetOnline(self):
        try:
            clientID = int(self.uiChat.listWidgetOnline.currentItem().text())
            toolTip = self.uiChat.listWidgetOnline.currentItem().toolTip()
            if toolTip != 'admin' and self.activateState == 3:
                if toolTip == 'request':
                    key = self.clientKeys[clientID]
                else:
                    key = None
                sendDict = {'nameRoom': self.nameRoom,
                            'clientID': clientID,
                            'keyClient': key,
                            'toolTip': toolTip}
                self.WidgetOnline.emit(sendDict)
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
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
            self.clientKeys = requests
            if admin in users:
                users.remove(admin)
                itemWidget = QtWidgets.QListWidgetItem(str(admin))
                itemWidget.setBackground(QColor(255, 142, 142))
                itemWidget.setToolTip("admin")
                self.uiChat.listWidgetOnline.addItem(itemWidget)
            for item in users:
                itemWidget = QtWidgets.QListWidgetItem(str(item))
                itemWidget.setBackground(QColor(142, 255, 203))
                itemWidget.setToolTip("user")
                self.uiChat.listWidgetOnline.addItem(itemWidget)
            for item in self.clientKeys.keys():
                itemWidget = QtWidgets.QListWidgetItem(str(item))
                itemWidget.setBackground(QColor(214, 142, 255))
                itemWidget.setToolTip("request")
                self.uiChat.listWidgetOnline.addItem(itemWidget)
                self.writeInClientKeysRSA(item, self.clientKeys[item], 'purple')
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
        return None

    def writeMSG(self, message, prefix, encrypt):
        try:
            import datetime
            timeChat = datetime.datetime.today().strftime("%H:%M:%S")
            timeChat = '<font color=\"black\">[' + timeChat + ']</font>'
            if encrypt:
                message = self.decryptTextFromAES(message)
            textToWindowChat = "<font color=\"black\">" + \
                               timeChat + prefix + ": " + message + "</font><br>"
            self.writeTextInWindowChat(textToWindowChat)
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
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
            key256 = self.keyRoomAES[self.currentCountKey]
            if key256 is None:
                return message
            else:
                BS = 16
                message = message + (BS - len(message) % BS) * chr(BS - len(message) % BS)
                iv = Random.new().read(AES.block_size)
                cipher = AES.new(key256, AES.MODE_CFB, iv)
                enc = base64.b64encode(iv + cipher.encrypt(message)).decode('utf-8')
                return enc
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return 'error ' + message

    def decryptTextFromAES(self, message):
        try:
            key256 = self.keyRoomAES[self.currentCountKey]
            if key256 is None:
                return message
            else:
                BS = 16
                enc = base64.b64decode(message)
                iv = enc[:BS]
                cipher = AES.new(key256, AES.MODE_CFB, iv)
                s = cipher.decrypt(enc[AES.block_size:]).decode('utf-8')
                return s[0:-ord(s[-1])]
        except Exception as errorTry:
            self.excaptionWrite(errorTry)
            return 'error ' + message

    def getActivateCodeRoom(self):
        return self.activateState

    def setKeyRoomAES(self, key):
        self.keyRoomAES.append(key)
        self.currentCountKey = self.currentCountKey + 1
        return None

    def getKeyRoomAES(self):
        return self.keyRoomAES[self.currentCountKey]

    def excaptionWrite(self, errorTry):
        import inspect
        nameFun = inspect.stack()[1][3]
        errorMsg = 'nameFun: ' + str(nameFun) + '. TRY: ' + str(errorTry)
        errorSend = {'command': '-sError', 'type': 'orange',
                     'text': errorMsg, 'room': self.nameRoom, 'address': None}
        self.ErrorCommand.emit(errorSend)
        return None
