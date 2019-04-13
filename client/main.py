from PyQt5.QtCore import Qt, QPoint, QRect, QSize
from PyQt5.QtGui import QPainter, QPen, QColor
from PyQt5.QtWidgets import QApplication, QWidget, QDesktopWidget
from form_slots import MainWindowSlots


class MainWindow(MainWindowSlots):
    def __init__(self, form):
        self.setupUi(form)
        form.resizeEvent = self.resizeEvent
        qr = form.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        form.move(qr.topLeft())
        self.keyPressEventOldMessage = self.lineEditSendMsg.keyPressEvent
        self.points = []
        self.line = QPoint(130, 0)
        self.colorPen = [9, 0, 255]
        self.connect_slots()

    def connect_slots(self):
        self.lineEditSendMsg.keyPressEvent = self.buttonSendEnterMSG

        self.pushButtonDisconnect.clicked.connect(self.buttonDisconnect)
        self.pushButtonSendMsg.clicked.connect(self.buttonSendMessage)
        self.pushButtonConnect.clicked.connect(self.buttonConnect)

        self.pushButtonGenNewKeysRSA.clicked.connect(self.buttonGenKeysRSA)
        self.pushButtonGenAES.clicked.connect(self.buttonGenKeyAES)
        self.pushButtonClearPoints.clicked.connect(self.buttonClearPoints)

        self.pushButtonCreateRoom.clicked.connect(self.buttonCreateNewRoom)
        self.listWidgetRooms.itemDoubleClicked.connect(self.doubleClickedWidgetOnline)
        self.listWidgetRequests.itemDoubleClicked.connect(self.doubleClickedWidgetRequests)
        self.pushButtonExitRoom.clicked.connect(self.buttonExitRoom)

        self.widget.mousePressEvent = self.mousePressEventWidgetRandom
        self.widget.mouseReleaseEvent = self.mouseReleaseEventWidgetRandom
        self.widget.mouseMoveEvent = self.mouseMoveEventWidgetRandom
        self.widget.paintEvent = self.paintEventWidgetRandom
        self.widgetColor.mousePressEvent = self.mousePressEventColor
        self.widgetColor.mouseMoveEvent = self.mouseMoveEventColor
        self.widgetColor.paintEvent = self.paintEventColor

    def buttonSendEnterMSG(self, event):
        if event.key() == Qt.Key_Return:
            self.buttonSendMessage()
        else:
            self.keyPressEventOldMessage(event)
        return None

    def buttonClearPoints(self):
        self.points = []
        self.widget.update()
        self.textEditRandomNumber.setText('')
        self.randomPointsArt = None
        return None

    def mousePressEventWidgetRandom(self, event):
        size = self.horizontalSliderSizePoint.value()
        self.points.append({'pos': event.pos(), 'color': self.colorPen, 'size': size})
        self.widget.update()
        return None

    def mouseMoveEventWidgetRandom(self, event):
        size = self.horizontalSliderSizePoint.value()
        self.points.append({'pos': event.pos(), 'color': self.colorPen, 'size': size})
        self.widget.update()
        return None

    def mouseReleaseEventWidgetRandom(self, event):  # Генерация рандомного числа
        if event is None:
            return
        for point in self.points:
            pos = hex(point['pos'].x()) + hex(point['pos'].y())
            color = hex(point['color'][0]) + hex(point['color'][1]) + hex(point['color'][2])
            size = hex(point['size'])
            self.randomPointsArt = pos + color + size
        randomRealTextEdit = self.randomGeneratorPointsArt(512)
        self.textEditRandomNumber.setText(str(randomRealTextEdit))
        return None

    def paintEventWidgetRandom(self, event):
        if event is None:
            return None
        if self.points is None:
            return None
        painter = QPainter()
        painter.begin(self.widget)
        self.drawPoints(painter)
        painter.end()
        return None

    def drawPoints(self, painter):
        for point in self.points:
            painter.setPen(QPen(QColor(point['color'][0], point['color'][1], point['color'][2]), point['size']))
            painter.drawPoint(point['pos'])
        return None

    def mousePressEventColor(self, event):
        self.line = event.pos()
        self.widgetColor.update()
        return None

    def mouseMoveEventColor(self, event):
        self.line = event.pos()
        self.widgetColor.update()
        return None

    def paintEventColor(self, event):
        if event is None:
            return None
        painter = QPainter()
        painter.begin(self.widgetColor)
        self.drawLine(painter)
        painter.end()
        return None

    def drawLine(self, painter):
        pos = self.line
        if (pos.x() > 230) or (pos.x() < 0):
            return None
        self.colorPen = GetRGBColor(pos.x())
        pen = QPen(QColor(255, 255, 255), 2, Qt.SolidLine)
        painter.setPen(pen)
        painter.drawLine(pos.x(), 0, pos.x(), 30)
        return None

    def resizeEvent(self, event):
        w = event.size().width()
        h = event.size().height()
        self.tabWidget.setFixedWidth(w - 15)
        self.tabWidget.setFixedHeight(h - 70)
        w_tabWidget = self.tabWidget.width()
        h_tabWidget = self.tabWidget.height()

        self.labelYourID.setGeometry(QRect(QPoint(10, h_tabWidget + 44), QSize(151, 31)))
        self.listWidgetRequests.setGeometry(QRect(QPoint(11, 105), QSize(119, h_tabWidget - 145)))

        self.textEditRandomNumber.setGeometry(QRect(QPoint(10, h_tabWidget - 120), QSize(w_tabWidget - 25, 81)))
        self.frame.setGeometry(QRect(QPoint(10, 50), QSize(w_tabWidget - 25, h_tabWidget - 180)))
        self.widget.setGeometry(QRect(QPoint(10, 10), QSize(w_tabWidget - 25, h_tabWidget - 180)))
        self.labelPlaceForArt.setGeometry(QRect(QPoint(0, 0), QSize(w_tabWidget - 25, h_tabWidget - 180)))

        self.labelOnline.setGeometry(QRect(QPoint(w_tabWidget - 135, 7), QSize(123, 20)))
        self.listWidgetRooms.setGeometry(QRect(QPoint(w_tabWidget - 135, 32), QSize(123, h_tabWidget - 209)))
        self.lineEditNameNewRoom.setGeometry(QRect(QPoint(w_tabWidget - 135, h_tabWidget - 171), QSize(123, 20)))
        self.pushButtonCreateRoom.setGeometry(QRect(QPoint(w_tabWidget - 135, h_tabWidget - 145), QSize(123, 20)))
        self.pushButtonExitRoom.setGeometry(QRect(QPoint(w_tabWidget - 135, h_tabWidget - 120), QSize(123, 20)))
        self.pushButtonSendMsg.setGeometry(QRect(QPoint(w_tabWidget - 135, h_tabWidget - 70), QSize(123, 30)))

        self.labelNameRoom.setGeometry(QRect(QPoint(5, 7), QSize(w_tabWidget - 150, 20)))
        self.textEditGlobal.setGeometry(QRect(QPoint(5, 32), QSize(w_tabWidget - 150, h_tabWidget - 122)))
        self.lineEditSendMsg.setGeometry(QRect(QPoint(5, h_tabWidget - 87), QSize(w_tabWidget - 150, 50)))
        return None


def GetRGBColor(value):
    rgb = int(value * 6.7)
    r = 250
    g = 0
    b = 0
    while g < 255:
        if rgb <= 0:
            break
        rgb = rgb - 1
        g = g + 1
    while r > 0:
        if rgb <= 0:
            break
        rgb = rgb - 1
        r = r - 1
    while b < 255:
        if rgb <= 0:
            break
        rgb = rgb - 1
        b = b + 1
    while g > 0:
        if rgb <= 0:
            break
        rgb = rgb - 1
        g = g - 1
    while r < 255:
        if rgb <= 0:
            break
        rgb = rgb - 1
        r = r + 1
    while b > 0:
        if rgb <= 0:
            break
        rgb = rgb - 1
        b = b - 1

    return [r, g, b]


if __name__ == '__main__':
    import sys

    app = QApplication(sys.argv)
    window = QWidget()
    ui = MainWindow(window)
    window.show()
    sys.exit(app.exec_())
