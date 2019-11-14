# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'areyousure.ui'
#
# Created by: PyQt5 UI code generator 5.13.0
#
# WARNING! All changes made in this file will be lost!


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(549, 166)
        self.gridLayout_2 = QtWidgets.QGridLayout(Form)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setObjectName("gridLayout")
        self.push_No = QtWidgets.QPushButton(Form)
        self.push_No.setObjectName("push_No")
        self.gridLayout.addWidget(self.push_No, 1, 0, 1, 1)
        self.push_Yes = QtWidgets.QPushButton(Form)
        self.push_Yes.setObjectName("push_Yes")
        self.gridLayout.addWidget(self.push_Yes, 1, 1, 1, 1)
        self.label_sure = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.label_sure.setFont(font)
        self.label_sure.setObjectName("label_sure")
        self.gridLayout.addWidget(self.label_sure, 0, 0, 1, 2, QtCore.Qt.AlignHCenter)
        self.gridLayout_2.addLayout(self.gridLayout, 0, 0, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.push_No.setText(_translate("Form", "No"))
        self.push_Yes.setText(_translate("Form", "Yes"))
        self.label_sure.setText(_translate("Form", "Are you sure?"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
