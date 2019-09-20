#! /usr/bin/env python3.

import sys
import subprocess
from PyQt5 import QtWidgets
from src.GUI.python_files.BATT5_GUI import Ui_BATT5
from src.GUI.python_files.popups.errors import ErrFile, Errx86, ErrBFile
from src.GUI.python_files.popups.newProjectWind import NewProject


class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()
        self.window = Ui_BATT5()
        self.window.setupUi(self)

        # Clicking on browse button calls showFileExplorer method
        self.window.dpmPluginStructure_button.clicked.connect(self.showFileExplorer)

        # Clicking on browse button calls showErrFile method
        self.window.commentSave_button.clicked.connect(self.showErrFile)

        # Clicking on New.. menu bar calls showFileExplorer method
        self.window.actionNew_Project.triggered.connect(self.showNewProject)

    # Shows NewProject window TODO: There's a bug here can't figure it out.
    def showNewProject(self):
        self.window = NewProject()
        # self.window.setupUi(self)
        # self.window.show()

    # Should open up file explorer TODO: Don't know if it actually works, need to integrate file selection.
    def showFileExplorer(self):
        subprocess.Popen(r'explorer')

    # Shows ErrFile window
    def showErrFile(self):
        self.window = ErrFile()
        self.window.show()

    # Shows Errx86 window
    def showErrx86(self):
        self.window = Errx86()
        self.window.show()

    # Shows ErrBFile window
    def showErrBFile(self):
        self.window = ErrBFile()
        self.window.show()


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
