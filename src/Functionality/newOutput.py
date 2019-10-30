import sys

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QTreeWidgetItem
from numpy import unicode
import xml.etree.ElementTree as ET
import os

from src.Functionality.output import Output
from src.GUI.python_files.popups.outputFieldView import OutputWindow
from src.GUI.python_files.popups.errors import ErrEmptyFields

output = Output


class NOutputWindow(QtWidgets.QDialog):
    def __init__(self):
        super(NOutputWindow, self).__init__()
        self.window = OutputWindow()
        self.window.setupUi(self)

        
        # browse button pressed
        self.window.browseOutput.clicked.connect(self.showFileExplorer)
        # generate button pressed
        self.window.generateOutput.clicked.connect(self.generateOutputXML)

    # ---- Extracts File Location -----------------------------------------------------------------------
    def showFileExplorer(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open Folder')
        self.window.path_lineEdit.setText(name)
        self.setProperties()

    # ---- Extracts Text From Fields and Assigns Them To Output Object and creates xml file -------
    def generateOutputXML(self):
        if self.window.lineEdit.text() == "":
            self.showErr()
        elif self.window.textEdit.toPlainText() == "":
            self.showErr()
        elif self.window.lineEdit_2.text() == "":
            self.showErr()
        else:
            # Set Name
            global output
            name = self.window.lineEdit.text()
            output.set_name(self, name)

            # Set Description
            description = self.window.textEdit.toPlainText()
            output.set_description(self, description)

            # select file
            file = self.window.lineEdit_2.text()
            project.set_file(self, file)

            # Create xml file for the new output
            cur_path = os.getcwd()
            name = name.replace(" ", "")
            f = os.path.join(cur_path, '..', 'Configurations', name + '.xml')
            self.createXML(f, cur_path)

            # close window
            self.accept()
            self.close()

    # ---- Creates the xml file associated with the new output --------------------------
    def createXML(self, file, cur_path):
        global output
        try:
            with open(file, "w") as f:
                newOutput = open(os.path.join(cur_path, '..', 'Configurations', 'newOutput.xml'), 'r')
                f.write(newOutput.read())
                newOutput.close()
                f.close()
            tree = ET.parse(file)
            root = tree.getroot()
            for child in root.iter():
                if child.tag == "Output":
                    child.set('name', output.get_name(self))
                    child.set('file', output.get_file(self))
                    child.set('description', output.get_description(self))
            tree.write(file)
        except FileNotFoundError:
            pass

    def accept(self):
        self.obj = output
        super(NOutputWindow, self).accept()

    def getOutput(self):
        return self.obj

    # ---- Show Error Message ---------------------------------
    def showErr(self):
        self.windowEF = ErrEmptyFields()
        self.windowEF.show()

    

def main():
    app = QtWidgets.QApplication(sys.argv)
    application = NOutputWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
