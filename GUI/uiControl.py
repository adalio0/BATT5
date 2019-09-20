#! /usr/bin/env python3.

import sys
import subprocess
from PyQt5 import QtWidgets
from BATT5_GUI import Ui_BATT5
from popups.errors import ErrFile, Errx86, ErrBFile


class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()
        self.window = Ui_BATT5()
        self.window.setupUi(self)

        # self.window.browse_button.clicked.connect(self.showErrFile)
        self.window.commentSave_button.clicked.connect(self.showErrFile)

    def showFileExplorer(self):
        subprocess.Popen(r'explorer')

    def showErrFile(self):
        self.window = ErrFile()
        self.window.show()


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
