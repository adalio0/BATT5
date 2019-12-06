import sys
import os
import glob
from pathlib import Path

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox

from src.GUI.python_files.popups.documentationView import Documentation_Window
from src.Functionality.Display.search import searchDocumentation


class DocumentationWindow(QtWidgets.QDialog):
    def __init__(self):
        super(DocumentationWindow, self).__init__()
        self.window = Documentation_Window()
        self.window.setupUi(self)
        self.setWindowTitle("Documentation")

        self.populateDoc()
        self.window.saveButton.setVisible(False)
        self.window.dDocumentView_textEdit.setReadOnly(True)

        self.window.documentView_lineEdit.textChanged.connect(self.callSearchDocumentation)
        self.window.documentView_listWidget.itemSelectionChanged.connect(self.showFile)

        self.window.addButton.clicked.connect(self.showFileExplorer)
        self.window.deleteButton.clicked.connect(self.showConfirmationDeleteProject)

        self.window.editButton.setShortcut('Ctrl+E')
        self.window.editButton.clicked.connect(self.edit)
        self.window.saveButton.setShortcut('Ctrl+S')
        self.window.saveButton.clicked.connect(self.save)

    # ---- Main methods for the window --------------------------------------------------------------------------

    # Gets all the .txt files inside the BATT5/Documentation path and display them
    def populateDoc(self):
        path = Path(__file__).parents[2].as_posix() + '/Documentation/'
        for file in sorted(glob.glob(path + "/**/" + '*.txt', recursive=True)):
            self.window.documentView_listWidget.addItem(file.split(path)[-1].split('.txt')[0])

    # When a file is selected on the list, will display its contents on the text field
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

    # When searching for something call the search functionality
    def callSearchDocumentation(self):
        try:
            searchDocumentation(self.window.documentView_lineEdit.text(), self.window.documentView_listWidget)
        except AttributeError:
            pass

    # ---- Save, Delete, Edit methods -----------------------------------------------------------------------------

    # When clicking the save button the file currently being edited will update accordingly
    def save(self):
        path = Path(__file__).parents[2].as_posix() + '/Documentation/'
        name = self.window.documentView_listWidget.currentItem().text()

        file = open((path + name + '.txt'), 'w')
        text = self.window.dDocumentView_textEdit.toPlainText()
        file.write(text)
        file.close()

    # When clicking the delete button, the currently selected file will be deleted from the BATT5/Documentation path
    def delete(self):
        path = Path(__file__).parents[2].as_posix() + '/Documentation/'
        name = self.window.documentView_listWidget.currentItem().text()

        if os.path.exists(path + name + ".txt"):
            os.remove(path + name + ".txt")
        else:
            print("The file does not exist")

        self.window.documentView_listWidget.clear()
        self.populateDoc()

    # When clicking the edit button, the currently selected file will be open for editing
    def edit(self):
        if self.window.documentView_listWidget.currentItem():
            if self.window.editButton.text() == "Edit":
                self.window.saveButton.setVisible(True)
                self.window.editButton.setText("Done")
                self.window.dDocumentView_textEdit.setReadOnly(False)
                self.showFile()
            else:
                self.window.saveButton.setVisible(False)
                self.window.editButton.setText("Edit")
                self.window.dDocumentView_textEdit.setReadOnly(True)
        else:
            QMessageBox.question(self, "Error Message: No file selected.",
                                 "Select a file to edit first.",
                                 QMessageBox.Ok)

    # ---- Methods to call show windows --------------------------------------------------------------------------

    # When clicking the add function, opens up a file explorer so user can add a previously created text file
    def showFileExplorer(self):
        path = Path(__file__).parents[2].as_posix() + '/Documentation/'

        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Add File", "", "Text Files (*.txt)", options=options)

        try:
            fileToSave = open(name, 'r')
            text = fileToSave.read()

            file = open((path + name.split('/')[-1].split('.')[0] + '.txt'), 'w+')
            file.write(text)
            fileToSave.close()
            file.close()

            self.window.documentView_listWidget.clear()
            self.populateDoc()
        except FileNotFoundError:
            pass

    def showConfirmationDeleteProject(self):
        name = self.window.documentView_listWidget.currentItem().text()
        choice = QMessageBox.question(self, 'Warning',
                                      "Are you sure you want to delete document: {}?".format(name),
                                      QMessageBox.Yes | QMessageBox.No)
        if choice == QMessageBox.Yes:
            self.delete()
        else:
            pass
def main():
    app = QtWidgets.QApplication(sys.argv)
    application = DocumentationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
