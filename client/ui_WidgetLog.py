# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Forms/WidgetLog.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_FormLog(object):
    def setupUi(self, FormLog):
        FormLog.setObjectName("FormLog")
        FormLog.resize(640, 480)
        FormLog.setMinimumSize(QtCore.QSize(640, 480))
        FormLog.setMaximumSize(QtCore.QSize(640, 480))
        self.tabWidget = QtWidgets.QTabWidget(FormLog)
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 640, 481))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.textEditMainLog = QtWidgets.QTextEdit(self.tab)
        self.textEditMainLog.setGeometry(QtCore.QRect(0, 0, 632, 405))
        self.textEditMainLog.setMinimumSize(QtCore.QSize(460, 0))
        self.textEditMainLog.setUndoRedoEnabled(True)
        self.textEditMainLog.setReadOnly(True)
        self.textEditMainLog.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByKeyboard|QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextBrowserInteraction|QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.textEditMainLog.setObjectName("textEditMainLog")
        self.checkBox = QtWidgets.QCheckBox(self.tab)
        self.checkBox.setEnabled(False)
        self.checkBox.setGeometry(QtCore.QRect(10, 415, 111, 22))
        self.checkBox.setObjectName("checkBox")
        self.pushButtonClearMainLog = QtWidgets.QPushButton(self.tab)
        self.pushButtonClearMainLog.setGeometry(QtCore.QRect(540, 410, 88, 30))
        self.pushButtonClearMainLog.setObjectName("pushButtonClearMainLog")
        self.tabWidget.addTab(self.tab, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.textEditRequestsLog = QtWidgets.QTextEdit(self.tab_3)
        self.textEditRequestsLog.setGeometry(QtCore.QRect(0, 0, 632, 405))
        self.textEditRequestsLog.setMinimumSize(QtCore.QSize(460, 0))
        self.textEditRequestsLog.setUndoRedoEnabled(True)
        self.textEditRequestsLog.setReadOnly(True)
        self.textEditRequestsLog.setTextInteractionFlags(QtCore.Qt.LinksAccessibleByKeyboard|QtCore.Qt.LinksAccessibleByMouse|QtCore.Qt.TextBrowserInteraction|QtCore.Qt.TextSelectableByKeyboard|QtCore.Qt.TextSelectableByMouse)
        self.textEditRequestsLog.setObjectName("textEditRequestsLog")
        self.pushButtonClearRequestsLog = QtWidgets.QPushButton(self.tab_3)
        self.pushButtonClearRequestsLog.setGeometry(QtCore.QRect(540, 410, 88, 30))
        self.pushButtonClearRequestsLog.setObjectName("pushButtonClearRequestsLog")
        self.tabWidget.addTab(self.tab_3, "")

        self.retranslateUi(FormLog)
        self.tabWidget.setCurrentIndex(0)
        self.pushButtonClearMainLog.clicked.connect(self.textEditMainLog.clear)
        self.pushButtonClearRequestsLog.clicked.connect(self.textEditRequestsLog.clear)
        QtCore.QMetaObject.connectSlotsByName(FormLog)

    def retranslateUi(self, FormLog):
        _translate = QtCore.QCoreApplication.translate
        FormLog.setWindowTitle(_translate("FormLog", "Log"))
        self.textEditMainLog.setHtml(_translate("FormLog", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Noto Sans\'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.checkBox.setText(_translate("FormLog", "Detailed Log"))
        self.pushButtonClearMainLog.setText(_translate("FormLog", "Clear Log"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("FormLog", "Main"))
        self.textEditRequestsLog.setHtml(_translate("FormLog", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'Noto Sans\'; font-size:10pt; font-weight:400; font-style:normal;\">\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>"))
        self.pushButtonClearRequestsLog.setText(_translate("FormLog", "Clear Log"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("FormLog", "Client-Server requests"))

