# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'test.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(635, 511)
        Form.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.tabWidget = QtWidgets.QTabWidget(Form)
        self.tabWidget.setEnabled(True)
        self.tabWidget.setGeometry(QtCore.QRect(10, 50, 611, 441))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.layoutWidget = QtWidgets.QWidget(self.tab)
        self.layoutWidget.setGeometry(QtCore.QRect(10, 13, 591, 391))
        self.layoutWidget.setObjectName("layoutWidget")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.layoutWidget)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.pushButton_6 = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_6.setEnabled(False)
        self.pushButton_6.setMaximumSize(QtCore.QSize(16777215, 20))
        self.pushButton_6.setObjectName("pushButton_6")
        self.gridLayout_2.addWidget(self.pushButton_6, 3, 3, 1, 1)
        self.lineEdit = QtWidgets.QPlainTextEdit(self.layoutWidget)
        self.lineEdit.setMaximumSize(QtCore.QSize(16777215, 50))
        self.lineEdit.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.lineEdit.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout_2.addWidget(self.lineEdit, 6, 0, 2, 3)
        self.pushButton_10 = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_10.setEnabled(False)
        self.pushButton_10.setMaximumSize(QtCore.QSize(16777215, 20))
        self.pushButton_10.setObjectName("pushButton_10")
        self.gridLayout_2.addWidget(self.pushButton_10, 4, 3, 1, 1)
        self.label_6 = QtWidgets.QLabel(self.layoutWidget)
        self.label_6.setMaximumSize(QtCore.QSize(80, 16777215))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.gridLayout_2.addWidget(self.label_6, 0, 0, 1, 1)
        self.label_17 = QtWidgets.QLabel(self.layoutWidget)
        font = QtGui.QFont()
        font.setFamily("Serif")
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label_17.setFont(font)
        self.label_17.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.label_17.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_17.setTextFormat(QtCore.Qt.AutoText)
        self.label_17.setObjectName("label_17")
        self.gridLayout_2.addWidget(self.label_17, 0, 1, 1, 2)
        self.textEdit_Global = QtWidgets.QTextEdit(self.layoutWidget)
        self.textEdit_Global.setMinimumSize(QtCore.QSize(460, 0))
        self.textEdit_Global.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByKeyboard|QtCore.Qt.LinksAccessibleByMouse)
        self.textEdit_Global.setObjectName("textEdit_Global")
        self.gridLayout_2.addWidget(self.textEdit_Global, 1, 0, 5, 3)
        self.listWidget = QtWidgets.QListWidget(self.layoutWidget)
        self.listWidget.setEditTriggers(QtWidgets.QAbstractItemView.DoubleClicked|QtWidgets.QAbstractItemView.EditKeyPressed)
        self.listWidget.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.listWidget.setObjectName("listWidget")
        self.gridLayout_2.addWidget(self.listWidget, 1, 3, 1, 1)
        self.label_11 = QtWidgets.QLabel(self.layoutWidget)
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_11.setFont(font)
        self.label_11.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_11.setAutoFillBackground(False)
        self.label_11.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.label_11.setObjectName("label_11")
        self.gridLayout_2.addWidget(self.label_11, 0, 3, 1, 1, QtCore.Qt.AlignHCenter)
        self.lineEdit_3 = QtWidgets.QLineEdit(self.layoutWidget)
        self.lineEdit_3.setEnabled(False)
        self.lineEdit_3.setMaximumSize(QtCore.QSize(16777215, 20))
        font = QtGui.QFont()
        font.setPointSize(8)
        self.lineEdit_3.setFont(font)
        self.lineEdit_3.setMaxLength(30)
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.gridLayout_2.addWidget(self.lineEdit_3, 2, 3, 1, 1)
        self.pushButton_3 = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButton_3.setEnabled(False)
        self.pushButton_3.setObjectName("pushButton_3")
        self.gridLayout_2.addWidget(self.pushButton_3, 7, 3, 1, 1)
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.groupBox = QtWidgets.QGroupBox(self.tab_2)
        self.groupBox.setEnabled(True)
        self.groupBox.setGeometry(QtCore.QRect(10, 10, 581, 51))
        self.groupBox.setMaximumSize(QtCore.QSize(16777215, 60))
        self.groupBox.setTitle("")
        self.groupBox.setObjectName("groupBox")
        self.layoutWidget1 = QtWidgets.QWidget(self.groupBox)
        self.layoutWidget1.setGeometry(QtCore.QRect(11, 10, 561, 34))
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.gridLayout = QtWidgets.QGridLayout(self.layoutWidget1)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.label_2 = QtWidgets.QLabel(self.layoutWidget1)
        self.label_2.setLineWidth(1)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 0, 2, 1, 1)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.layoutWidget1)
        self.lineEdit_2.setMaximumSize(QtCore.QSize(60, 16777215))
        self.lineEdit_2.setMaxLength(8)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.gridLayout.addWidget(self.lineEdit_2, 0, 3, 1, 1)
        self.label_8 = QtWidgets.QLabel(self.layoutWidget1)
        self.label_8.setObjectName("label_8")
        self.gridLayout.addWidget(self.label_8, 0, 4, 1, 1)
        self.lineEdit_9 = QtWidgets.QLineEdit(self.layoutWidget1)
        self.lineEdit_9.setMaximumSize(QtCore.QSize(200, 16777215))
        self.lineEdit_9.setText("")
        self.lineEdit_9.setMaxLength(20)
        self.lineEdit_9.setObjectName("lineEdit_9")
        self.gridLayout.addWidget(self.lineEdit_9, 0, 5, 1, 1)
        self.label = QtWidgets.QLabel(self.layoutWidget1)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.lineEdit_1 = QtWidgets.QLineEdit(self.layoutWidget1)
        self.lineEdit_1.setMaximumSize(QtCore.QSize(100, 16777215))
        self.lineEdit_1.setMaxLength(15)
        self.lineEdit_1.setObjectName("lineEdit_1")
        self.gridLayout.addWidget(self.lineEdit_1, 0, 1, 1, 1)
        self.layoutWidget2 = QtWidgets.QWidget(self.tab_2)
        self.layoutWidget2.setGeometry(QtCore.QRect(10, 70, 101, 331))
        self.layoutWidget2.setObjectName("layoutWidget2")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.layoutWidget2)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label_4 = QtWidgets.QLabel(self.layoutWidget2)
        self.label_4.setAlignment(QtCore.Qt.AlignCenter)
        self.label_4.setObjectName("label_4")
        self.verticalLayout.addWidget(self.label_4)
        self.listWidget_2 = QtWidgets.QListWidget(self.layoutWidget2)
        self.listWidget_2.setEditTriggers(QtWidgets.QAbstractItemView.DoubleClicked|QtWidgets.QAbstractItemView.EditKeyPressed)
        self.listWidget_2.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        self.listWidget_2.setObjectName("listWidget_2")
        self.verticalLayout.addWidget(self.listWidget_2)
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.tabWidget_2 = QtWidgets.QTabWidget(self.tab_3)
        self.tabWidget_2.setGeometry(QtCore.QRect(10, 10, 591, 411))
        self.tabWidget_2.setTabPosition(QtWidgets.QTabWidget.West)
        self.tabWidget_2.setTabShape(QtWidgets.QTabWidget.Triangular)
        self.tabWidget_2.setObjectName("tabWidget_2")
        self.tab_5 = QtWidgets.QWidget()
        self.tab_5.setObjectName("tab_5")
        self.layoutWidget3 = QtWidgets.QWidget(self.tab_5)
        self.layoutWidget3.setGeometry(QtCore.QRect(10, 50, 541, 331))
        self.layoutWidget3.setObjectName("layoutWidget3")
        self.gridLayout_6 = QtWidgets.QGridLayout(self.layoutWidget3)
        self.gridLayout_6.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_6.setObjectName("gridLayout_6")
        self.label_10 = QtWidgets.QLabel(self.layoutWidget3)
        self.label_10.setMaximumSize(QtCore.QSize(16777215, 15))
        self.label_10.setObjectName("label_10")
        self.gridLayout_6.addWidget(self.label_10, 2, 0, 1, 1)
        self.label_9 = QtWidgets.QLabel(self.layoutWidget3)
        self.label_9.setMaximumSize(QtCore.QSize(16777215, 15))
        self.label_9.setObjectName("label_9")
        self.gridLayout_6.addWidget(self.label_9, 0, 0, 1, 1)
        self.textEdit_5 = QtWidgets.QTextEdit(self.layoutWidget3)
        self.textEdit_5.setMaximumSize(QtCore.QSize(16777215, 130))
        self.textEdit_5.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_5.setObjectName("textEdit_5")
        self.gridLayout_6.addWidget(self.textEdit_5, 3, 0, 1, 1)
        self.textEdit_4 = QtWidgets.QTextEdit(self.layoutWidget3)
        self.textEdit_4.setMaximumSize(QtCore.QSize(16777215, 130))
        self.textEdit_4.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_4.setObjectName("textEdit_4")
        self.gridLayout_6.addWidget(self.textEdit_4, 1, 0, 1, 1)
        self.layoutWidget4 = QtWidgets.QWidget(self.tab_5)
        self.layoutWidget4.setGeometry(QtCore.QRect(10, 10, 541, 36))
        self.layoutWidget4.setObjectName("layoutWidget4")
        self.gridLayout_7 = QtWidgets.QGridLayout(self.layoutWidget4)
        self.gridLayout_7.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_7.setObjectName("gridLayout_7")
        self.comboBox = QtWidgets.QComboBox(self.layoutWidget4)
        self.comboBox.setMaximumSize(QtCore.QSize(70, 16777215))
        self.comboBox.setEditable(False)
        self.comboBox.setMaxVisibleItems(10)
        self.comboBox.setMaxCount(10)
        self.comboBox.setMinimumContentsLength(0)
        self.comboBox.setDuplicatesEnabled(False)
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.gridLayout_7.addWidget(self.comboBox, 0, 2, 1, 1)
        self.pushButton_4 = QtWidgets.QPushButton(self.layoutWidget4)
        self.pushButton_4.setMaximumSize(QtCore.QSize(200, 16777215))
        self.pushButton_4.setObjectName("pushButton_4")
        self.gridLayout_7.addWidget(self.pushButton_4, 0, 0, 1, 1)
        self.label_15 = QtWidgets.QLabel(self.layoutWidget4)
        self.label_15.setMaximumSize(QtCore.QSize(40, 15))
        self.label_15.setObjectName("label_15")
        self.gridLayout_7.addWidget(self.label_15, 0, 3, 1, 1)
        self.label_14 = QtWidgets.QLabel(self.layoutWidget4)
        self.label_14.setMaximumSize(QtCore.QSize(140, 16777215))
        self.label_14.setObjectName("label_14")
        self.gridLayout_7.addWidget(self.label_14, 0, 1, 1, 1)
        self.tabWidget_2.addTab(self.tab_5, "")
        self.tab_8 = QtWidgets.QWidget()
        self.tab_8.setObjectName("tab_8")
        self.textEdit_7 = QtWidgets.QTextEdit(self.tab_8)
        self.textEdit_7.setGeometry(QtCore.QRect(10, 40, 541, 41))
        self.textEdit_7.setMaximumSize(QtCore.QSize(16777215, 70))
        self.textEdit_7.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_7.setObjectName("textEdit_7")
        self.label_18 = QtWidgets.QLabel(self.tab_8)
        self.label_18.setGeometry(QtCore.QRect(10, 20, 549, 15))
        self.label_18.setMaximumSize(QtCore.QSize(16777215, 15))
        self.label_18.setObjectName("label_18")
        self.pushButton_11 = QtWidgets.QPushButton(self.tab_8)
        self.pushButton_11.setGeometry(QtCore.QRect(390, 90, 161, 25))
        self.pushButton_11.setObjectName("pushButton_11")
        self.tabWidget_2.addTab(self.tab_8, "")
        self.tab_6 = QtWidgets.QWidget()
        self.tab_6.setObjectName("tab_6")
        self.textEdit_6 = QtWidgets.QTextEdit(self.tab_6)
        self.textEdit_6.setGeometry(QtCore.QRect(10, 30, 541, 151))
        self.textEdit_6.setMaximumSize(QtCore.QSize(16777215, 200))
        self.textEdit_6.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_6.setObjectName("textEdit_6")
        self.label_12 = QtWidgets.QLabel(self.tab_6)
        self.label_12.setGeometry(QtCore.QRect(10, 10, 549, 15))
        self.label_12.setMaximumSize(QtCore.QSize(16777215, 15))
        self.label_12.setObjectName("label_12")
        self.tabWidget_2.addTab(self.tab_6, "")
        self.tab_7 = QtWidgets.QWidget()
        self.tab_7.setObjectName("tab_7")
        self.textEdit_8 = QtWidgets.QTextEdit(self.tab_7)
        self.textEdit_8.setGeometry(QtCore.QRect(10, 30, 541, 351))
        self.textEdit_8.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.textEdit_8.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_8.setObjectName("textEdit_8")
        self.label_19 = QtWidgets.QLabel(self.tab_7)
        self.label_19.setGeometry(QtCore.QRect(10, 10, 549, 15))
        self.label_19.setMaximumSize(QtCore.QSize(16777215, 15))
        self.label_19.setObjectName("label_19")
        self.tabWidget_2.addTab(self.tab_7, "")
        self.tabWidget.addTab(self.tab_3, "")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setObjectName("tab_4")
        self.layoutWidget_2 = QtWidgets.QWidget(self.tab_4)
        self.layoutWidget_2.setGeometry(QtCore.QRect(10, 10, 581, 36))
        self.layoutWidget_2.setObjectName("layoutWidget_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.layoutWidget_2)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.pushButton_12 = QtWidgets.QPushButton(self.layoutWidget_2)
        self.pushButton_12.setObjectName("pushButton_12")
        self.horizontalLayout.addWidget(self.pushButton_12)
        self.label_20 = QtWidgets.QLabel(self.layoutWidget_2)
        self.label_20.setMaximumSize(QtCore.QSize(60, 15))
        self.label_20.setObjectName("label_20")
        self.horizontalLayout.addWidget(self.label_20)
        self.lineEdit_5 = QtWidgets.QLineEdit(self.layoutWidget_2)
        self.lineEdit_5.setMaximumSize(QtCore.QSize(40, 16777215))
        self.lineEdit_5.setInputMethodHints(QtCore.Qt.ImhNone)
        self.lineEdit_5.setInputMask("")
        self.lineEdit_5.setText("")
        self.lineEdit_5.setMaxLength(32767)
        self.lineEdit_5.setObjectName("lineEdit_5")
        self.horizontalLayout.addWidget(self.lineEdit_5)
        self.textEdit_2 = QtWidgets.QTextEdit(self.tab_4)
        self.textEdit_2.setGeometry(QtCore.QRect(10, 50, 591, 351))
        self.textEdit_2.setObjectName("textEdit_2")
        self.tabWidget.addTab(self.tab_4, "")
        self.layoutWidget5 = QtWidgets.QWidget(Form)
        self.layoutWidget5.setGeometry(QtCore.QRect(10, 10, 251, 36))
        self.layoutWidget5.setObjectName("layoutWidget5")
        self.gridLayout_4 = QtWidgets.QGridLayout(self.layoutWidget5)
        self.gridLayout_4.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_4.setObjectName("gridLayout_4")
        self.pushButton_2 = QtWidgets.QPushButton(self.layoutWidget5)
        self.pushButton_2.setObjectName("pushButton_2")
        self.gridLayout_4.addWidget(self.pushButton_2, 0, 0, 1, 1)
        self.pushButton = QtWidgets.QPushButton(self.layoutWidget5)
        self.pushButton.setEnabled(False)
        self.pushButton.setObjectName("pushButton")
        self.gridLayout_4.addWidget(self.pushButton, 0, 1, 1, 1)
        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setGeometry(QtCore.QRect(10, 490, 111, 21))
        font = QtGui.QFont()
        font.setPointSize(8)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")

        self.retranslateUi(Form)
        self.tabWidget.setCurrentIndex(0)
        self.tabWidget_2.setCurrentIndex(0)
        self.comboBox.setCurrentIndex(1)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "FBBL"))
        self.pushButton_6.setText(_translate("Form", "Create Room"))
        self.pushButton_10.setText(_translate("Form", "Exit Room"))
        self.label_6.setText(_translate("Form", "<html><head/><body><p align=\"right\">Name Room:</p></body></html>"))
        self.label_17.setText(_translate("Form", "<html><head/><body><p align=\"center\">-</p></body></html>"))
        self.label_11.setText(_translate("Form", "Online:"))
        self.pushButton_3.setText(_translate("Form", "Send"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("Form", "Chat"))
        self.label_2.setText(_translate("Form", "Port:"))
        self.lineEdit_2.setText(_translate("Form", "8000"))
        self.label_8.setText(_translate("Form", "Nick Name:"))
        self.label.setText(_translate("Form", "IP:"))
        self.lineEdit_1.setText(_translate("Form", "127.0.0.1"))
        self.label_4.setText(_translate("Form", "Requests:"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("Form", "Setting"))
        self.label_10.setText(_translate("Form", "My Privat Key"))
        self.label_9.setText(_translate("Form", "My Public Key"))
        self.comboBox.setItemText(0, _translate("Form", "4096"))
        self.comboBox.setItemText(1, _translate("Form", "2048"))
        self.pushButton_4.setText(_translate("Form", "Gen new keys"))
        self.label_15.setText(_translate("Form", "Bit"))
        self.label_14.setText(_translate("Form", "Cryptographic stength"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_5), _translate("Form", "My keys"))
        self.label_18.setText(_translate("Form", "Key Room ( AES-256 )"))
        self.pushButton_11.setText(_translate("Form", "Gen new AES-256 keys"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_8), _translate("Form", "Key Room"))
        self.label_12.setText(_translate("Form", "Public Key server\'s"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_6), _translate("Form", "Server Keys"))
        self.label_19.setText(_translate("Form", "Public Keys Clients"))
        self.tabWidget_2.setTabText(self.tabWidget_2.indexOf(self.tab_7), _translate("Form", "Clients keys"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("Form", "Keys"))
        self.pushButton_12.setText(_translate("Form", "HAND Gen Random number"))
        self.label_20.setText(_translate("Form", "seconds:"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_4), _translate("Form", "Gen Random"))
        self.pushButton_2.setText(_translate("Form", "Connect to server"))
        self.pushButton.setText(_translate("Form", "Disconnect"))
        self.label_3.setText(_translate("Form", "your id:"))

