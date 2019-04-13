from PyQt5.QtWidgets import QApplication, QWidget, QDesktopWidget
from PyQt5.QtCore import Qt
from form_slots import MainWindowSlots


class MainWindow(MainWindowSlots):
    def __init__(self, form):
        self.setupUi(form)
        self.keyPressEventOldMessage = self.lineEditSendMsg.keyPressEvent
        self.connect_slots()

    def connect_slots(self):
        self.lineEditSendMsg.keyPressEvent = self.button_send_msg_enter

        self.pushButtonDisconnect.clicked.connect(self.button_disconnect)
        self.pushButtonSendMsg.clicked.connect(self.button_send_msg)
        self.pushButtonConnect.clicked.connect(self.button_connect)

        self.pushButtonGenNewKeysRSA.clicked.connect(self.button_gen_rsa_keys)
        self.pushButtonGenAES.clicked.connect(self.button_gen_aes_keys)
        self.pushButtonClearPoints.clicked.connect(self.buttonClearPoints)

        self.pushButtonCreateRoom.clicked.connect(self.button_create_new_room)
        self.listWidgetRooms.itemDoubleClicked.connect(self.double_clicked_widget_in_room)
        self.listWidgetRequests.itemDoubleClicked.connect(self.double_clicked_widget2_add_new_user_in_room)
        self.pushButtonExitRoom.clicked.connect(self.button_exit_room)

        self.widget.mousePressEvent = self.mousePressEventWidgetRandom
        self.widget.mouseReleaseEvent = self.mouseReleaseEventWidgetRandom
        self.widget.mouseMoveEvent = self.mouseMoveEventWidgetRandom
        self.widget.paintEvent = self.paintEventWidgetRandom
        self.widgetColor.mousePressEvent = self.mousePressEventColor
        self.widgetColor.mouseMoveEvent = self.mouseMoveEventColor
        self.widgetColor.paintEvent = self.paintEventColor

    def button_send_msg_enter(self, event):
        if event.key() == Qt.Key_Return:
            self.button_send_msg()
        else:
            self.keyPressEventOldMessage(event)

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
        return None


if __name__ == '__main__':
    import sys

    app = QApplication(sys.argv)
    window = QWidget()
    ui = MainWindow(window)
    window.show()
    sys.exit(app.exec_())
