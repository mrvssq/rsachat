from PyQt5.QtCore import QRect
from PyQt5.QtWidgets import QApplication, QDesktopWidget, QMainWindow, QWidget, QDialog
from main_slots import MainWindowSlots
from genRandom_slots import GenRandomSlots
from WidgetMyKeys_ui import Ui_FormMyKeys
from DialogAbout_ui import Ui_DialogAbout
from WidgetLog_ui import Ui_FormLog


class MainWindow(MainWindowSlots):
    def __init__(self, mainForm):

        self.setupUi(mainForm)
        mainForm.resizeEvent = self.resizeEventGlobalWindow
        self.frame.resizeEvent = self.resizeEventFrame
        mainForm.closeEvent = self.closeEvent
        qr = mainForm.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        mainForm.move(qr.topLeft())
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setStretchFactor(2, 2)

        self.randomPointsArt = None

        self.listWidgetRooms.hide()
        self.frame.hide()

        self.myKeysForm = QWidget()
        self.logForm = QWidget()
        self.aboutForm = QDialog()

        self.uiMyKeys = Ui_FormMyKeys()
        self.uiLog = Ui_FormLog()
        self.uiAbout = Ui_DialogAbout()

        self.createFormMyKeysSlots()
        self.createLogSlots()
        self.createAboutSlots()
        self.connect_slots()

        self.widgetGenRandom = QWidget(self.myKeysForm)
        self.uiGenRandom = GenRandomSlots(self.widgetGenRandom)
        self.createWidgetGenRandomSlots()

    def closeEvent(self, event):
        self.myKeysForm.close()
        self.aboutForm.close()
        self.logForm.close()
        event.accept()
        return None

    def createFormMyKeysSlots(self):
        self.uiMyKeys.setupUi(self.myKeysForm)
        self.uiMyKeys.pushButtonGenNewKeysRSA.clicked.connect(self.buttonShowRandomGen)
        self.uiMyKeys.pushButtonSave.clicked.connect(self.buttonSaveKeysRSA)
        self.myKeysForm.hideEvent = self.hideEventMyKeys
        return None

    def createWidgetGenRandomSlots(self):
        self.uiGenRandom.setupUi(self.widgetGenRandom)
        self.widgetGenRandom.mouseReleaseEvent = self.genRSA
        self.widgetGenRandom.hide()
        self.widgetGenRandom.setGeometry(QRect(40, 10, 250, 130))
        self.widgetGenRandom.setMinimumSize(250, 130)
        self.widgetGenRandom.setMaximumSize(250, 130)

    def createLogSlots(self):
        self.uiLog.setupUi(self.logForm)
        return None

    def createAboutSlots(self):
        self.uiAbout.setupUi(self.aboutForm)
        return None

    def connect_slots(self):
        self.listWidgetRooms.itemDoubleClicked.connect(self.doubleClickedWidgetRooms)
        self.listWidgetRooms.itemClicked.connect(self.clickedDisplayWidgetRooms)
        self.actionConnect.triggered.connect(self.buttonConnect)
        self.pushButtonConnect.clicked.connect(self.buttonConnect)
        self.actionDisconnect.triggered.connect(self.buttonDisconnect)
        self.actionExit.triggered.connect(QApplication.instance().quit)
        self.actionShow_Rooms.triggered.connect(self.showWidgetRooms)
        self.actionMy_keys.triggered.connect(self.showWidgetMyKeys)
        self.actionLog.triggered.connect(self.showWidgetLog)
        self.actionAbout.triggered.connect(self.showWidgetAbout)
        #   self.splitter.splitterMoved.connect(self.splitterFunMoved)
        return None

    def resizeEventFrame(self, event):
        w = event.size().width()
        self.labelYourID.setGeometry(QRect(0, 0, w, 30))
        return None

    def resizeEventGlobalWindow(self, event):
        w = event.size().width()
        h = event.size().height()
        self.splitter.setGeometry(QRect(0, 0, w, h))
        self.frameConnect.setGeometry(QRect(int(w/2-100), int(h/2-75), 200, 130))
        return None


if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)

    window = QMainWindow()
    ui = MainWindow(window)
    window.show()

    sys.exit(app.exec_())
