# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Forms/DialogSettingsRoom.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_DialogSettingsRoom(object):
    def setupUi(self, DialogSettingsRoom):
        DialogSettingsRoom.setObjectName("DialogSettingsRoom")
        DialogSettingsRoom.resize(500, 400)
        DialogSettingsRoom.setMinimumSize(QtCore.QSize(500, 400))
        DialogSettingsRoom.setMaximumSize(QtCore.QSize(500, 400))
        self.textEditPublicKeysClients = QtWidgets.QTextEdit(DialogSettingsRoom)
        self.textEditPublicKeysClients.setGeometry(QtCore.QRect(10, 110, 481, 251))
        self.textEditPublicKeysClients.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.textEditPublicKeysClients.setFrameShadow(QtWidgets.QFrame.Plain)
        self.textEditPublicKeysClients.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEditPublicKeysClients.setObjectName("textEditPublicKeysClients")
        self.labelPubKeysClient = QtWidgets.QLabel(DialogSettingsRoom)
        self.labelPubKeysClient.setGeometry(QtCore.QRect(10, 90, 141, 15))
        self.labelPubKeysClient.setMaximumSize(QtCore.QSize(16777215, 15))
        self.labelPubKeysClient.setObjectName("labelPubKeysClient")
        self.textEditKeyRoomAES = QtWidgets.QTextEdit(DialogSettingsRoom)
        self.textEditKeyRoomAES.setGeometry(QtCore.QRect(10, 30, 481, 41))
        self.textEditKeyRoomAES.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.textEditKeyRoomAES.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEditKeyRoomAES.setObjectName("textEditKeyRoomAES")
        self.labelKeyRoom = QtWidgets.QLabel(DialogSettingsRoom)
        self.labelKeyRoom.setGeometry(QtCore.QRect(10, 10, 549, 15))
        self.labelKeyRoom.setMaximumSize(QtCore.QSize(16777215, 15))
        self.labelKeyRoom.setObjectName("labelKeyRoom")
        self.pushButtonGenAES = QtWidgets.QPushButton(DialogSettingsRoom)
        self.pushButtonGenAES.setGeometry(QtCore.QRect(330, 77, 161, 25))
        self.pushButtonGenAES.setObjectName("pushButtonGenAES")
        self.pushButtonClose = QtWidgets.QPushButton(DialogSettingsRoom)
        self.pushButtonClose.setGeometry(QtCore.QRect(400, 370, 91, 25))
        self.pushButtonClose.setObjectName("pushButtonClose")
        self.pushButtonSave = QtWidgets.QPushButton(DialogSettingsRoom)
        self.pushButtonSave.setGeometry(QtCore.QRect(300, 370, 91, 25))
        self.pushButtonSave.setObjectName("pushButtonSave")

        self.retranslateUi(DialogSettingsRoom)
        self.pushButtonClose.clicked.connect(DialogSettingsRoom.reject)
        QtCore.QMetaObject.connectSlotsByName(DialogSettingsRoom)

    def retranslateUi(self, DialogSettingsRoom):
        _translate = QtCore.QCoreApplication.translate
        DialogSettingsRoom.setWindowTitle(_translate("DialogSettingsRoom", "Settings Room"))
        self.labelPubKeysClient.setText(_translate("DialogSettingsRoom", "Public Keys Requests"))
        self.labelKeyRoom.setText(_translate("DialogSettingsRoom", "Key Room ( AES-256 )"))
        self.pushButtonGenAES.setText(_translate("DialogSettingsRoom", "Gen new AES-256 keys"))
        self.pushButtonClose.setText(_translate("DialogSettingsRoom", "Close"))
        self.pushButtonSave.setText(_translate("DialogSettingsRoom", "Save"))

