#! /usr/bin/env python3.

import os
import sys
import subprocess
import xml.etree.ElementTree as ET

from PyQt5 import QtWidgets
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from src.GUI.python_files.BATT5_GUI import Ui_BATT5
from src.GUI.python_files.popups.errors import ErrFile, Errx86, ErrRadare
from src.GUI.python_files.popups.newProjectWind import NewProject
from src.GUI.python_files.popups.xmlEditor import XMLEditor


class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()
        self.window = Ui_BATT5()
        self.window.setupUi(self)

        # Clicking on Plugin Structure browse button calls showFileExplorer method
        self.window.dpmPluginStructure_button.clicked.connect(self.showFileExplorer)

        # Clicking on Plugin Predefined browse button calls showFileExplorer method (xmlEditor for now)
        self.window.dpmPluginPredefined_button.clicked.connect(self.xmlEditor)

        # Clicking on New.. menu bar calls showNewProject method
        self.window.actionNew_Project.triggered.connect(self.showNewProject)

    # Opens up an xml (file) editor TODO: If we open this window it creates a bug where we can't select a file in the
    # TODO:                                 main window need to figure out a fix.
    def xmlEditor(self):
        self.window = XMLEditor()
        self.window.show()

        cur_path = os.getcwd()
        file = os.path.join(cur_path, '..', 'Configurations', 'country_data.xml')
        tree = ET.parse(file)
        root = tree.getroot()

        # print(root.tag)

    # Shows NewProject window TODO: There's a bug here can't figure it out.
    def showNewProject(self):
        self.window = NewProject()
        # self.window.show()

    # Open up file explorer to select a file
    def showFileExplorer(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmPluginStructure_lineEdit.setText(name)

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
        self.window = ErrRadare()
        self.window.show()


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
