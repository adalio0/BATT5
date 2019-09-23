#!/usr/bin/env python3

import sys
import r2pipe
from PyQt5 import QtWidgets
from GUI.ui import Ui_MainWindow


class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()
        self.window = Ui_MainWindow()
        self.window.setupUi(self)
        # self.window.staticAnalysisRun_button.clicked.connect(statrunbutton(self))
        self.window.POIContentArea_text.setText(statrunbutton(self))

def statrunbutton(self):
    analyedFile = r2pipe.open("C:\Windows\System32\ping.exe")
    imports = analyedFile.cmd("fj")
    return imports

def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
