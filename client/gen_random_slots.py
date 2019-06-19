from ui_widget_gen_random import Ui_FormGenRandom
from PyQt5.QtGui import QColor, QPainter, QPen
from Crypto.Random import random
from Crypto import Random


class GenRandomSlots(Ui_FormGenRandom):
    def __init__(self, widgetGenRandom):
        self.widgetGenRandom = widgetGenRandom
        self.randomPointsArt = None
        self.points = []
        self.color = QColor(100, 100, 100)
        self.size = 5
        self.slots()

    def slots(self):
        self.widgetGenRandom.showEvent = self.destructor
        self.widgetGenRandom.hideEvent = self.destructor
        self.widgetGenRandom.mousePressEvent = self.mousePressEventWidgetRandom
        self.widgetGenRandom.mouseMoveEvent = self.mousePressEventWidgetRandom
        self.widgetGenRandom.paintEvent = self.paintEventWidgetRandom

    def calculateRandomPointsArt(self):
        lenPoints = len(self.points)
        minimum = 200
        maximum = 50000
        if minimum <= lenPoints <= maximum:
            sump = ''
            for point in self.points:
                sump += str(point.x() * point.y())
            self.randomPointsArt = bytes(sump, 'utf-8')
            return True
        elif lenPoints < minimum or lenPoints > maximum:
            return False

    def setRandomPointsArt(self, rand):
        self.randomPointsArt = rand
        return None

    def getRandomPointsArt(self):
        return self.randomPointsArt

    def randomGeneratorPointsArt(self, n):
        if self.randomPointsArt is None:
            return Random.get_random_bytes(n)
        else:
            sumBytes = self.randomPointsArt
        arr = [byte for byte in sumBytes]
        Random.random.shuffle(arr)
        sumBytes = bytes(arr)
        count = n - len(sumBytes)
        if count > 0:
            sumBytes = sumBytes + Random.get_random_bytes(count)
        if count < 0:
            sumBytes = sumBytes[:n]
        return sumBytes

    def destructor(self, event):
        if event is None:
            return None
        self.points = []
        self.randomPointsArt = None
        self.widgetGenRandom.update()
        self.progressBarPoints.setValue(0)
        self.labelGenRandom.setText('   Please draw. Points: 0')
        self.progressBarPoints.setMaximum(200)

    def mousePressEventWidgetRandom(self, event):
        oldPoint = None
        if self.points:
            oldPoint = self.points[-1]
        if event.pos() != oldPoint:
            self.points.append(event.pos())
            count = len(self.points)
            self.progressBarPoints.setValue(count)
            self.labelGenRandom.setText('   Please draw. Points: ' + str(count))
            self.labelXY.setText(str(event.pos().x()) + ':' + str(event.pos().y()))
            self.widgetGenRandom.update()
        return None

    def paintEventWidgetRandom(self, event):
        if event is None:
            return None
        if self.points is None:
            return None
        painter = QPainter()
        painter.begin(self.widgetGenRandom)
        self.drawPoints(painter)
        painter.end()
        return None

    def drawPoints(self, painter):
        for point in self.points:
            painter.setPen(QPen(self.color, self.size))
            painter.drawPoint(point)
        return None
