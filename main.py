from PyQt5.QtWidgets import QApplication, QWidget, QDesktopWidget
from test_slots import MainWindowSlots


class MainWindow(MainWindowSlots):
    def __init__(self, form):
        self.setupUi(form)
        self.connect_slots()

    def connect_slots(self):
        self.pushButton.clicked.connect(self.button_disconnect)
        self.pushButton_3.clicked.connect(self.button_send_msg)
        self.pushButton_2.clicked.connect(self.button_connect)

        self.pushButton_4.clicked.connect(self.button_gen_rsa_keys)

        self.pushButton_11.clicked.connect(self.button_gen_aes_keys)
        self.pushButton_12.clicked.connect(self.button_hand_gen_random_number_keys)

        self.pushButton_6.clicked.connect(self.button_create_new_room)
        self.listWidget.itemDoubleClicked.connect(self.double_clicked_widget_in_room)
        self.listWidget_2.itemDoubleClicked.connect(self.double_clicked_widget2_add_new_user_in_room)
        self.pushButton_10.clicked.connect(self.button_exit_room)

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
