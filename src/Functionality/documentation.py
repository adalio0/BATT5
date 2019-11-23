import sys
import os
import glob
from pathlib import Path

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox, QFileDialog

from src.GUI.python_files.popups.documentationView import Documentation_Window
from src.GUI.python_files.popups.fileEditor import FileEditor

edit = False


class DocumentationWindow(QtWidgets.QDialog):
    def __init__(self):
        super(DocumentationWindow, self).__init__()
        self.window = Documentation_Window()
        self.window.setupUi(self)
        self.populateDoc()

        self.window.saveButton.setVisible(False)
        self.window.dDocumentView_textEdit.setReadOnly(True)

        self.window.documentView_listWidget.itemSelectionChanged.connect(self.show)
        self.window.addButton.clicked.connect(self.showFileExplorer)
        self.window.editButton.clicked.connect(self.edit)
        self.window.saveButton.clicked.connect(self.save)

    # ---- Methods ------------------------------------------------------------------------------

    def populateDoc(self):
        path = Path(__file__).parents[2].as_posix() + '/Documentation/'
        for file in glob.glob(path + "/**/" + '*.txt', recursive=True):
            self.window.documentView_listWidget.addItem(file.split(path)[-1].split('.txt')[0])

    def save(self):
        name, _ = QtWidgets.QFileDialog.getSaveFileName(self, 'Save File', options=QFileDialog.DontUseNativeDialog)

        try:
            file = open(name, 'w')
            text = self.window.dDocumentView_textEdit.toPlainText()
            file.write(text)
            file.close()
        except FileNotFoundError:
            pass

    def show(self):
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

    def edit(self):
        global edit
        if not edit:
            self.window.saveButton.setVisible(True)
            self.window.editButton.setText("Done")
            self.window.dDocumentView_textEdit.setReadOnly(False)
            edit = True
            self.show()
        else:
            self.window.saveButton.setVisible(False)
            self.window.editButton.setText("Edit")
            self.window.dDocumentView_textEdit.setReadOnly(True)
            edit = False

    def showFileExplorer(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Browse", "",
                                                        "All Files (*);;Text Files (*.txt)", options=options)
        print(name)
        self.window.documentView_listWidget.addItem(name)

    # ---- Show Error Message ------------------------------------------

    def showErr(self):
        QMessageBox.question(self, "Error Message: Missing Fields",
                             "All fields must be filled to in order to create a Project",
                             QMessageBox.Ok)


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = DocumentationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
