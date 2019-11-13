import sys
import pymongo
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QFileDialog
from PyQt5.QtWidgets import QTreeWidgetItem
from numpy import unicode
from jinja2 import Environment, FileSystemLoader
import xml.etree.ElementTree as ET
import os
from os.path import expanduser

from src.Functionality.output import Output
from src.GUI.python_files.popups.outputFieldView import OutputWindow
from src.GUI.python_files.popups.errors import ErrEmptyFields

output = Output
file_loader = FileSystemLoader('templates')
env = Environment(loader = file_loader)

class NOutputWindow(QtWidgets.QDialog):
    def __init__(self):
        super(NOutputWindow, self).__init__()
        self.window = OutputWindow()
        self.window.setupUi(self)
        # browse button pressed
        self.window.browseOutput.clicked.connect(self.showFileExplorer)
        # generate button pressed
        self.window.generateOutput.clicked.connect(self.generateTemp)

    # ---- Extracts File Location -----------------------------------------------------------------------
    def showFileExplorer(self):
        input_file = QFileDialog.getExistingDirectory(None, 'Select a folder:', expanduser("~"))
        self.window.lineEdit_2.setText(input_file)
    # ---- Extracts Text From Fields and Assigns Them To Output Object and creates xml file -------
    def generateTemp(self):
        if self.window.lineEdit.text() == "":
            self.showErr()
        elif self.window.textEdit.toPlainText() == "":
            self.showErr()
        elif self.window.lineEdit_2.text() == "":
            self.showErr()
        else:
            self.insertOToDatabase()

            # close window
            self.accept()
            self.close()
    def insertOToDatabase(self):
        client = pymongo.MongoClient("mongodb://localhost:27017")
        db = client['output_data']
        output_db = db['output']

        results = {

            'name': self.window.lineEdit.text(),

            'description': self.window.textEdit.toPlainText(),

            'location': self.window.lineEdit_2.text(),

            
        }
        results_outcome = output_db.insert_one(results)
        
        name = self.window.lineEdit.text()
        description = self.window.textEdit.toPlainText()
        location = self.window.lineEdit_2.text()
        variables =['temp']
        functions =['temp']
        strings =['temp']
        dlls =['temp']

        template = env.get_template('networkScript.txt')
        script = template.render(variables = variables, strings = strings, functions = functions, dlls = dlls, name = name, location = location, description = description)
        file = os.path.join(location, name +".txt")
        final = open(file, "w")
        final.write(script)
        final.close()
        

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
