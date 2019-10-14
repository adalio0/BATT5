from PyQt5.QtWidgets import *
from PyQt5 import QtWidgets


class ErrFile(QWidget):
    def __init__(self):
        super(ErrFile, self).__init__()
        self.left = 450
        self.top = 250
        self.width = 420
        self.height = 150

        msg = QLabel("A project is associated with one binary file and cannot be saved \n"
                     "without a binary file. Please provide a binary file.")

        okButton = QPushButton("OK")

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(okButton)

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(msg)
        vbox.addLayout(hbox)

        self.setWindowTitle("Error Message: File Specified")
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.setLayout(vbox)

        okButton.clicked.connect(self.okClicked)

    def okClicked(self):
        self.close()


class Errx86(QWidget):
    def __init__(self):
        super(Errx86, self).__init__()
        self.left = 450
        self.top = 250
        self.width = 420
        self.height = 150

        msg = QLabel("The system only supports files that are of x86 architecture")

        okButton = QPushButton("OK")

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(okButton)

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(msg)
        vbox.addLayout(hbox)

        self.setWindowTitle("Error Message: x86 architecture binary file")
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.setLayout(vbox)

        okButton.clicked.connect(self.okClicked)

    def okClicked(self):
        self.close()


class ErrRadare(QWidget):
    def __init__(self):
        super(ErrRadare, self).__init__()
        self.left = 450
        self.top = 250
        self.width = 420
        self.height = 150

        msg = QLabel("(Returning any Radare2's error message if there are issues extracting\n"
                     "properties from the binary file.)")

        okButton = QPushButton("OK")

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(okButton)

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(msg)
        vbox.addLayout(hbox)

        self.setWindowTitle("Error Message: Binary File Property Extraction")
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.setLayout(vbox)

        okButton.clicked.connect(self.okClicked)

    def okClicked(self):
        self.close()


class ErrEmptyFields(QtWidgets.QWidget):
    def __init__(self):
        super(ErrEmptyFields, self).__init__()
        self.left = 450
        self.top = 250
        self.width = 300
        self.height = 50

        msg = QLabel("All fields must be filled to in order to create a Project")

        okButton = QPushButton("OK")

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(okButton)

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(msg)
        vbox.addLayout(hbox)

        self.setWindowTitle("Error Message: Missing Fields")
        self.setGeometry(self.left, self.top, self.width, self.height)
        self.setLayout(vbox)

        okButton.clicked.connect(self.okClicked)

    def okClicked(self):
        self.close()
