import sys
import os
import glob
from pathlib import Path

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox, QFileDialog

from src.GUI.python_files.popups.documentationView import Documentation_Window
from src.Functionality.search import searchDocumentation


class DocumentationWindow(QtWidgets.QDialog):
    def __init__(self):
        super(DocumentationWindow, self).__init__()
        self.window = Documentation_Window()
        self.window.setupUi(self)

        self.populateDoc()
        self.window.saveButton.setVisible(False)
        self.window.dDocumentView_textEdit.setReadOnly(True)

        self.window.documentView_lineEdit.textChanged.connect(self.callSearchDocumentation)
        self.window.documentView_listWidget.itemSelectionChanged.connect(self.showFile)

        self.window.addButton.clicked.connect(self.showFileExplorer)
        self.window.deleteButton.clicked.connect(self.delete)
        self.window.editButton.setShortcut('Ctrl+E')
        self.window.editButton.clicked.connect(self.edit)
        self.window.saveButton.setShortcut('Ctrl+S')
        self.window.saveButton.clicked.connect(self.save)

    # ---- Main methods for the window --------------------------------------------------------------------------

    def populateDoc(self):
        path = Path(__file__).parents[2].as_posix() + '/Documentation/'
        for file in glob.glob(path + "/**/" + '*.txt', recursive=True):
            self.window.documentView_listWidget.addItem(file.split(path)[-1].split('.txt')[0])

    def showFile(self):
        self.window.dDocumentView_textEdit.clear()
        if self.window.documentView_listWidget.currentItem():
            name = self.window.documentView_listWidget.currentItem().text()
            path = Path(__file__).parents[2].as_posix() + '/Documentation/'

            try:
                for file in glob.glob(path + "/**/" + (name + '.txt'), recursive=True):
                    file = open(file, 'r')
                    text = file.read()
                    self.window.dDocumentView_textEdit.setText(text)
                    file.close()
            except FileNotFoundError:
                pass

    # ---- Search functionality ----------------------------------------------------------------------------------

    def callSearchDocumentation(self):
        try:
            searchDocumentation(self.window.documentView_lineEdit.text(), self.window.documentView_listWidget)
        except AttributeError:
            pass

    # ---- Save, Delete, Edit methods -----------------------------------------------------------------------------

    def save(self):
        path = Path(__file__).parents[2].as_posix() + '/Documentation/'
        name = self.window.documentView_listWidget.currentItem().text()

        try:
            file = open((path + name + '.txt'), 'w')
            text = self.window.dDocumentView_textEdit.toPlainText()
            file.write(text)
            file.close()
        except FileNotFoundError:
            pass

    def delete(self):
        path = Path(__file__).parents[2].as_posix() + '/Documentation/'
        name = self.window.documentView_listWidget.currentItem().text()

        if os.path.exists(path + name + ".txt"):
            os.remove(path + name + ".txt")
        else:
            print("The file does not exist")

        self.window.documentView_listWidget.clear()
        self.populateDoc()

    def edit(self):
        if self.window.editButton.text() == "Edit":
            self.window.saveButton.setVisible(True)
            self.window.editButton.setText("Done")
            self.window.dDocumentView_textEdit.setReadOnly(False)
            self.showFile()
        else:
            self.window.saveButton.setVisible(False)
            self.window.editButton.setText("Edit")
            self.window.dDocumentView_textEdit.setReadOnly(True)

    # ---- Methods to call show windows --------------------------------------------------------------------------

    def showErr(self):
        QMessageBox.question(self, "Error Message: Missing Fields",
                             "All fields must be filled to in order to create a Project",
                             QMessageBox.Ok)

    def showFileExplorer(self):
        path = Path(__file__).parents[2].as_posix() + '/Documentation/'

        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Add File", "",
                                                        "All Files (*);;Text Files (*.txt)", options=options)

        try:
            file = open((path + name.split('/')[-1].split('.')[0] + '.txt'), 'w+')
            contents = open(name, 'r')
            file.write(contents.read())
            contents.close()
            file.close()
            self.window.documentView_listWidget.clear()
            self.populateDoc()
        except UnicodeDecodeError:
            print('nah bitch')
            pass


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = DocumentationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
