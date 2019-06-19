# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Forms/main.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.setWindowModality(QtCore.Qt.NonModal)
        MainWindow.setEnabled(True)
        MainWindow.resize(640, 480)
        MainWindow.setMinimumSize(QtCore.QSize(640, 480))
        MainWindow.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        MainWindow.setLayoutDirection(QtCore.Qt.LeftToRight)
        MainWindow.setTabShape(QtWidgets.QTabWidget.Rounded)
        MainWindow.setDockNestingEnabled(False)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setEnabled(True)
        self.centralwidget.setObjectName("centralwidget")
        self.splitter = QtWidgets.QSplitter(self.centralwidget)
        self.splitter.setGeometry(QtCore.QRect(0, 0, 640, 451))
        self.splitter.setMidLineWidth(0)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setOpaqueResize(True)
        self.splitter.setHandleWidth(0)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setObjectName("splitter")
        self.splitterVer = QtWidgets.QSplitter(self.splitter)
        self.splitterVer.setOrientation(QtCore.Qt.Vertical)
        self.splitterVer.setOpaqueResize(False)
        self.splitterVer.setHandleWidth(0)
        self.splitterVer.setChildrenCollapsible(False)
        self.splitterVer.setObjectName("splitterVer")
        self.frame = QtWidgets.QFrame(self.splitterVer)
        self.frame.setMinimumSize(QtCore.QSize(0, 30))
        self.frame.setMaximumSize(QtCore.QSize(250, 30))
        self.frame.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.labelYourID = QtWidgets.QLabel(self.frame)
        self.labelYourID.setGeometry(QtCore.QRect(0, 0, 200, 30))
        self.labelYourID.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.labelYourID.setText("")
        self.labelYourID.setAlignment(QtCore.Qt.AlignCenter)
        self.labelYourID.setObjectName("labelYourID")
        self.listWidgetRooms = QtWidgets.QListWidget(self.splitterVer)
        self.listWidgetRooms.setMinimumSize(QtCore.QSize(142, 0))
        self.listWidgetRooms.setMaximumSize(QtCore.QSize(250, 16777215))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.listWidgetRooms.setFont(font)
        self.listWidgetRooms.setContextMenuPolicy(QtCore.Qt.DefaultContextMenu)
        self.listWidgetRooms.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.listWidgetRooms.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.listWidgetRooms.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustIgnored)
        self.listWidgetRooms.setEditTriggers(QtWidgets.QAbstractItemView.DoubleClicked|QtWidgets.QAbstractItemView.EditKeyPressed)
        self.listWidgetRooms.setTabKeyNavigation(False)
        self.listWidgetRooms.setDragEnabled(False)
        self.listWidgetRooms.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.listWidgetRooms.setObjectName("listWidgetRooms")
        self.stackedWidgetChats = QtWidgets.QStackedWidget(self.splitter)
        self.stackedWidgetChats.setMinimumSize(QtCore.QSize(0, 0))
        self.stackedWidgetChats.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.stackedWidgetChats.setObjectName("stackedWidgetChats")
        self.frameConnect = QtWidgets.QFrame(self.centralwidget)
        self.frameConnect.setGeometry(QtCore.QRect(220, 150, 200, 130))
        self.frameConnect.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.frameConnect.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frameConnect.setObjectName("frameConnect")
        self.layoutWidget = QtWidgets.QWidget(self.frameConnect)
        self.layoutWidget.setGeometry(QtCore.QRect(10, 10, 180, 112))
        self.layoutWidget.setObjectName("layoutWidget")
        self.gridLayout = QtWidgets.QGridLayout(self.layoutWidget)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        self.gridLayout.setObjectName("gridLayout")
        self.lineEditHost = QtWidgets.QLineEdit(self.layoutWidget)
        self.lineEditHost.setMaximumSize(QtCore.QSize(111, 16777215))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.lineEditHost.setFont(font)
        self.lineEditHost.setInputMask("")
        self.lineEditHost.setMaxLength(32767)
        self.lineEditHost.setObjectName("lineEditHost")
        self.gridLayout.addWidget(self.lineEditHost, 0, 0, 1, 1)
        self.lineEditPort = QtWidgets.QLineEdit(self.layoutWidget)
        self.lineEditPort.setMaximumSize(QtCore.QSize(61, 16777215))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.lineEditPort.setFont(font)
        self.lineEditPort.setMaxLength(8)
        self.lineEditPort.setObjectName("lineEditPort")
        self.gridLayout.addWidget(self.lineEditPort, 0, 1, 1, 1)
        self.lineEditNickName = QtWidgets.QLineEdit(self.layoutWidget)
        self.lineEditNickName.setMaximumSize(QtCore.QSize(181, 16777215))
        font = QtGui.QFont()
        font.setPointSize(10)
        font.setBold(False)
        font.setItalic(False)
        font.setWeight(50)
        self.lineEditNickName.setFont(font)
        self.lineEditNickName.setAutoFillBackground(False)
        self.lineEditNickName.setStyleSheet("")
        self.lineEditNickName.setText("")
        self.lineEditNickName.setMaxLength(20)
        self.lineEditNickName.setFrame(True)
        self.lineEditNickName.setDragEnabled(False)
        self.lineEditNickName.setObjectName("lineEditNickName")
        self.gridLayout.addWidget(self.lineEditNickName, 1, 0, 1, 2)
        self.pushButtonConnect = QtWidgets.QPushButton(self.layoutWidget)
        self.pushButtonConnect.setObjectName("pushButtonConnect")
        self.gridLayout.addWidget(self.pushButtonConnect, 2, 0, 1, 2)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 640, 30))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuOptions = QtWidgets.QMenu(self.menubar)
        self.menuOptions.setEnabled(True)
        self.menuOptions.setObjectName("menuOptions")
        self.menuInfo = QtWidgets.QMenu(self.menubar)
        self.menuInfo.setObjectName("menuInfo")
        self.menuView = QtWidgets.QMenu(self.menubar)
        self.menuView.setObjectName("menuView")
        MainWindow.setMenuBar(self.menubar)
        self.actionMy_keys = QtWidgets.QAction(MainWindow)
        self.actionMy_keys.setObjectName("actionMy_keys")
        self.actionKey_Rooms = QtWidgets.QAction(MainWindow)
        self.actionKey_Rooms.setEnabled(True)
        self.actionKey_Rooms.setObjectName("actionKey_Rooms")
        self.actionServer_keys = QtWidgets.QAction(MainWindow)
        self.actionServer_keys.setEnabled(False)
        self.actionServer_keys.setObjectName("actionServer_keys")
        self.actionClient_keys = QtWidgets.QAction(MainWindow)
        self.actionClient_keys.setObjectName("actionClient_keys")
        self.actionConnect = QtWidgets.QAction(MainWindow)
        self.actionConnect.setObjectName("actionConnect")
        self.actionExit = QtWidgets.QAction(MainWindow)
        self.actionExit.setObjectName("actionExit")
        self.actionAbout = QtWidgets.QAction(MainWindow)
        self.actionAbout.setCheckable(False)
        self.actionAbout.setObjectName("actionAbout")
        self.actionDisconnect = QtWidgets.QAction(MainWindow)
        self.actionDisconnect.setEnabled(False)
        self.actionDisconnect.setObjectName("actionDisconnect")
        self.actionGeneration = QtWidgets.QAction(MainWindow)
        self.actionGeneration.setObjectName("actionGeneration")
        self.actionClear = QtWidgets.QAction(MainWindow)
        self.actionClear.setObjectName("actionClear")
        self.actionGenerator_Random = QtWidgets.QAction(MainWindow)
        self.actionGenerator_Random.setObjectName("actionGenerator_Random")
        self.actionLog = QtWidgets.QAction(MainWindow)
        self.actionLog.setObjectName("actionLog")
        self.actionShow_Rooms = QtWidgets.QAction(MainWindow)
        self.actionShow_Rooms.setCheckable(True)
        self.actionShow_Rooms.setChecked(True)
        self.actionShow_Rooms.setObjectName("actionShow_Rooms")
        self.menuFile.addAction(self.actionConnect)
        self.menuFile.addAction(self.actionDisconnect)
        self.menuFile.addAction(self.actionExit)
        self.menuOptions.addAction(self.actionMy_keys)
        self.menuOptions.addAction(self.actionLog)
        self.menuInfo.addAction(self.actionAbout)
        self.menuView.addAction(self.actionShow_Rooms)
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuView.menuAction())
        self.menubar.addAction(self.menuOptions.menuAction())
        self.menubar.addAction(self.menuInfo.menuAction())

        self.retranslateUi(MainWindow)
        self.listWidgetRooms.setCurrentRow(-1)
        self.stackedWidgetChats.setCurrentIndex(-1)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "RSA Chat"))
        self.listWidgetRooms.setSortingEnabled(False)
        self.lineEditHost.setText(_translate("MainWindow", "127.0.0.1"))
        self.lineEditHost.setPlaceholderText(_translate("MainWindow", "Host"))
        self.lineEditPort.setText(_translate("MainWindow", "8000"))
        self.lineEditPort.setPlaceholderText(_translate("MainWindow", "Port"))
        self.lineEditNickName.setPlaceholderText(_translate("MainWindow", "Nick Name"))
        self.pushButtonConnect.setText(_translate("MainWindow", "Connect to Server"))
        self.menuFile.setTitle(_translate("MainWindow", "Fi&le"))
        self.menuOptions.setTitle(_translate("MainWindow", "Options"))
        self.menuInfo.setTitle(_translate("MainWindow", "I&nfo"))
        self.menuView.setTitle(_translate("MainWindow", "View"))
        self.actionMy_keys.setText(_translate("MainWindow", "&My keys"))
        self.actionKey_Rooms.setText(_translate("MainWindow", "&Room keys"))
        self.actionServer_keys.setText(_translate("MainWindow", "&Server keys"))
        self.actionClient_keys.setText(_translate("MainWindow", "Client keys"))
        self.actionConnect.setText(_translate("MainWindow", "&Connect"))
        self.actionExit.setText(_translate("MainWindow", "&Exit"))
        self.actionAbout.setText(_translate("MainWindow", "&About"))
        self.actionDisconnect.setText(_translate("MainWindow", "&Disconnect"))
        self.actionGeneration.setText(_translate("MainWindow", "&Generation"))
        self.actionClear.setText(_translate("MainWindow", "&Clear"))
        self.actionGenerator_Random.setText(_translate("MainWindow", "&Generator Random"))
        self.actionLog.setText(_translate("MainWindow", "&Log"))
        self.actionShow_Rooms.setText(_translate("MainWindow", "&Show Rooms"))

