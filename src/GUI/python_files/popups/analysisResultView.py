# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'analysisResultView.ui'
#
# Created by: PyQt5 UI code generator 5.13.1
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Analysis_Window(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(611, 506)
        self.horizontalLayout = QtWidgets.QHBoxLayout(Form)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.label_4 = QtWidgets.QLabel(Form)
        self.label_4.setObjectName("label_4")
        self.gridLayout_2.addWidget(self.label_4, 2, 0, 1, 1)
        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setObjectName("label_3")
        self.gridLayout_2.addWidget(self.label_3, 1, 0, 1, 1)
        self.deleteResult = QtWidgets.QPushButton(Form)
        self.deleteResult.setObjectName("deleteResult")
        self.gridLayout_2.addWidget(self.deleteResult, 3, 0, 1, 1, QtCore.Qt.AlignLeft)
        self.saveResult = QtWidgets.QPushButton(Form)
        self.saveResult.setObjectName("saveResult")
        self.gridLayout_2.addWidget(self.saveResult, 3, 1, 1, 1, QtCore.Qt.AlignRight)
        self.lineEdit_2 = QtWidgets.QLineEdit(Form)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.gridLayout_2.addWidget(self.lineEdit_2, 1, 1, 1, 1)
        self.textEdit = QtWidgets.QTextEdit(Form)
        self.textEdit.setObjectName("textEdit")
        self.gridLayout_2.addWidget(self.textEdit, 2, 1, 1, 1)
        self.label_2 = QtWidgets.QLabel(Form)
        self.label_2.setMinimumSize(QtCore.QSize(0, 30))
        self.label_2.setStyleSheet("background-color: rgb(182, 206, 227);")
        self.label_2.setObjectName("label_2")
        self.gridLayout_2.addWidget(self.label_2, 0, 0, 1, 2)
        self.gridLayout.addLayout(self.gridLayout_2, 7, 0, 1, 1)
        self.lineEdit = QtWidgets.QLineEdit(Form)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout.addWidget(self.lineEdit, 1, 0, 1, 1)
        self.label = QtWidgets.QLabel(Form)
        self.label.setMinimumSize(QtCore.QSize(0, 30))
        self.label.setStyleSheet("background-color: rgb(182, 206, 227);")
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.listWidget = QtWidgets.QListWidget(Form)
        self.listWidget.setObjectName("listWidget")
        item = QtWidgets.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtWidgets.QListWidgetItem()
        self.listWidget.addItem(item)
        item = QtWidgets.QListWidgetItem()
        self.listWidget.addItem(item)
        self.gridLayout.addWidget(self.listWidget, 3, 0, 1, 1)
        self.newResult = QtWidgets.QPushButton(Form)
        self.newResult.setObjectName("newResult")
        self.gridLayout.addWidget(self.newResult, 4, 0, 1, 1, QtCore.Qt.AlignRight)
        self.horizontalLayout.addLayout(self.gridLayout)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label_4.setText(_translate("Form", "Description"))
        self.label_3.setText(_translate("Form", "Name"))
        self.deleteResult.setText(_translate("Form", "Delete"))
        self.saveResult.setText(_translate("Form", "Save"))
        self.label_2.setText(_translate("Form", "                                                                                     Analysis Result Area"))
        self.lineEdit.setText(_translate("Form", "Search results.."))
        self.label.setText(_translate("Form", "                                                                                      Analysis Result View"))
        __sortingEnabled = self.listWidget.isSortingEnabled()
        self.listWidget.setSortingEnabled(False)
        item = self.listWidget.item(0)
        item.setText(_translate("Form", "Analysis Result A"))
        item = self.listWidget.item(1)
        item.setText(_translate("Form", "Analysis Result B"))
        item = self.listWidget.item(2)
        item.setText(_translate("Form", "Analysis Result C"))
        self.listWidget.setSortingEnabled(__sortingEnabled)
        self.newResult.setText(_translate("Form", "+"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Analysis_Window()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
