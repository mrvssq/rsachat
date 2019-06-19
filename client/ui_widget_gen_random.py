# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Forms/WidgetGenRandom.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_FormGenRandom(object):
    def setupUi(self, FormGenRandom):
        FormGenRandom.setObjectName("FormGenRandom")
        FormGenRandom.resize(250, 130)
        FormGenRandom.setStyleSheet("background-color: rgb(235, 235, 235);")
        self.labelGenRandom = QtWidgets.QLabel(FormGenRandom)
        self.labelGenRandom.setGeometry(QtCore.QRect(0, 0, 251, 18))
        self.labelGenRandom.setStyleSheet("")
        self.labelGenRandom.setTextFormat(QtCore.Qt.AutoText)
        self.labelGenRandom.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.labelGenRandom.setObjectName("labelGenRandom")
        self.pushButtonHide = QtWidgets.QPushButton(FormGenRandom)
        self.pushButtonHide.setGeometry(QtCore.QRect(230, 0, 20, 20))
        self.pushButtonHide.setStyleSheet("")
        self.pushButtonHide.setAutoExclusive(False)
        self.pushButtonHide.setAutoDefault(False)
        self.pushButtonHide.setDefault(False)
        self.pushButtonHide.setFlat(True)
        self.pushButtonHide.setObjectName("pushButtonHide")
        self.progressBarPoints = QtWidgets.QProgressBar(FormGenRandom)
        self.progressBarPoints.setGeometry(QtCore.QRect(10, 110, 231, 15))
        self.progressBarPoints.setMinimum(0)
        self.progressBarPoints.setMaximum(1000)
        self.progressBarPoints.setProperty("value", 0)
        self.progressBarPoints.setTextVisible(True)
        self.progressBarPoints.setOrientation(QtCore.Qt.Horizontal)
        self.progressBarPoints.setInvertedAppearance(False)
        self.progressBarPoints.setTextDirection(QtWidgets.QProgressBar.TopToBottom)
        self.progressBarPoints.setObjectName("progressBarPoints")
        self.labelXY = QtWidgets.QLabel(FormGenRandom)
        self.labelXY.setGeometry(QtCore.QRect(10, 50, 221, 20))
        self.labelXY.setStyleSheet("background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(0, 0, 0, 0), stop:1 rgba(255, 255, 255, 0));\n"
"color: rgb(194, 194, 194);")
        self.labelXY.setText("")
        self.labelXY.setAlignment(QtCore.Qt.AlignCenter)
        self.labelXY.setObjectName("labelXY")

        self.retranslateUi(FormGenRandom)
        self.pushButtonHide.clicked.connect(FormGenRandom.hide)
        QtCore.QMetaObject.connectSlotsByName(FormGenRandom)

    def retranslateUi(self, FormGenRandom):
        _translate = QtCore.QCoreApplication.translate
        FormGenRandom.setWindowTitle(_translate("FormGenRandom", "Random Generator"))
        self.labelGenRandom.setText(_translate("FormGenRandom", "   Please draw. Points: 0"))
        self.pushButtonHide.setText(_translate("FormGenRandom", "X"))
        self.progressBarPoints.setFormat(_translate("FormGenRandom", "minimum"))

