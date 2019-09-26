import sys
import os
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5 import QtCore, QtWidgets

# This class is used to create the XML editor window that will be used to save, modify or create new XML files.


class XMLEditor(QMainWindow):
    def __init__(self, parent=None):
        super(XMLEditor, self).__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("XML Editor")

        # --- Initializing menu bar items --------------------
        cur_path = os.getcwd().split("src")
        new_path = cur_path[0]

        newAction = QAction(QIcon(new_path + "src/icons/newDoc.png"), "New", self)
        newAction.setShortcut("Ctrl+N")
        newAction.setStatusTip("Create a new document from scratch.")
        newAction.triggered.connect(self.New)

        openAction = QAction(QIcon(new_path + "src/icons/openDoc.png"), "Open file", self)
        openAction.setStatusTip("Open existing document")
        openAction.setShortcut("Ctrl+O")
        openAction.triggered.connect(self.Open)

        saveAction = QAction(QIcon(new_path + "src/icons/save.png"), "Save", self)
        saveAction.setStatusTip("Save document")
        saveAction.setShortcut("Ctrl+S")
        saveAction.triggered.connect(self.Save)

        findAction = QAction(QIcon(new_path + "src/icons/find.png"), "Find", self)
        findAction.setStatusTip("Find words in your document")
        findAction.setShortcut("Ctrl+F")
        # findAction.triggered.connect(self.Find)

        cutAction = QAction(QIcon(new_path + "src/icons/cut.png"), "Cut to clipboard", self)
        cutAction.setStatusTip("Delete and copy text to clipboard")
        cutAction.setShortcut("Ctrl+X")
        cutAction.triggered.connect(self.Cut)

        copyAction = QAction(QIcon(new_path + "src/icons/copy.png"), "Copy to clipboard", self)
        copyAction.setStatusTip("Copy text to clipboard")
        copyAction.setShortcut("Ctrl+C")
        copyAction.triggered.connect(self.Copy)

        pasteAction = QAction(QIcon(new_path + "src/icons/paste.png"), "Paste from clipboard", self)
        pasteAction.setStatusTip("Paste text from clipboard")
        pasteAction.setShortcut("Ctrl+V")
        pasteAction.triggered.connect(self.Paste)

        undoAction = QAction(QIcon(new_path + "src/icons/undo.png"), "Undo last action", self)
        undoAction.setStatusTip("Undo last action")
        undoAction.setShortcut("Ctrl+Z")
        undoAction.triggered.connect(self.Undo)

        redoAction = QAction(QIcon(new_path + "src/icons/redo.png"), "Redo last undone thing", self)
        redoAction.setStatusTip("Redo last undone thing")
        redoAction.setShortcut("Ctrl+Y")
        redoAction.triggered.connect(self.Redo)

        closeAction = QAction(QIcon(new_path + "src/icons/redcross.png"), "Close window", self)
        closeAction.setStatusTip("Close window")
        closeAction.setShortcut("Ctrl+Q")
        closeAction.triggered.connect(self.Close)

        self.toolbar = self.addToolBar("Options")
        self.toolbar.addAction(newAction)
        self.toolbar.addAction(openAction)
        self.toolbar.addAction(saveAction)
        self.toolbar.addSeparator()
        self.toolbar.addSeparator()
        self.toolbar.addAction(findAction)
        self.toolbar.addAction(cutAction)
        self.toolbar.addAction(copyAction)
        self.toolbar.addAction(pasteAction)
        self.toolbar.addAction(undoAction)
        self.toolbar.addAction(redoAction)
        self.toolbar.addSeparator()
        self.toolbar.addSeparator()
        self.toolbar.addAction(closeAction)

        self.addToolBarBreak()

        # --- Menubar --------------------------------------

        menubar = self.menuBar()
        file = menubar.addMenu("File")
        edit = menubar.addMenu("Edit")
        view = menubar.addMenu("View")

        file.addAction(newAction)
        file.addAction(openAction)
        file.addAction(saveAction)

        edit.addAction(undoAction)
        edit.addAction(redoAction)
        edit.addAction(cutAction)
        edit.addAction(copyAction)
        edit.addAction(findAction)

        # --- Main window ----------------------------------

        self.lb1 = self.addToolBar("Format")
        self.lb1.setStyleSheet("font-size: 15px; ")

        self.text = QTextEdit(self)
        self.fileEdit = QTextEdit(self)
        self.text.setTabStopWidth(12)
        self.fileEdit.setTabStopWidth(12)

        self.stacked = QtWidgets.QStackedWidget()
        self.stacked.addWidget(self.text)
        self.stacked.addWidget(self.fileEdit)

        mainWidget = QtWidgets.QWidget()
        myLayout = QtWidgets.QVBoxLayout()

        mainWidget.setLayout(myLayout)
        myLayout.addWidget(self.stacked)
        self.setCentralWidget(mainWidget)

        self.statusBar()

        self.statusBar().showMessage("Ready")

        self.setGeometry(500, 500, 560, 450)

    def New(self):
        self.stacked.setCurrentWidget(self.text)
        self.text.clear()

    def Save(self):
        name, _ = QFileDialog.getSaveFileName(self, 'Save File', options=QFileDialog.DontUseNativeDialog)

        try:
            file = open(name, 'w')
            text = self.fileEdit.toPlainText()
            file.write(text)
            file.close()
        except FileNotFoundError:
            pass

    def Close(self):
        choice = QMessageBox.question(self, 'Message',
                                      "Quit?", QMessageBox.Yes |
                                      QMessageBox.No, QMessageBox.No)

        if choice == QMessageBox.Yes:
            self.close()
        else:
            pass

    def Open(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')

        try:
            file = open(name, 'r')

            self.editor()

            with file:
                text = file.read()
                self.fileEdit.setText(text)
            file.close()
        except FileNotFoundError:
            pass

    def editor(self):
        self.stacked.setCurrentWidget(self.fileEdit)

    def Undo(self):
        self.text.undo()

    def Redo(self):
        self.text.redo()

    def Cut(self):
        self.text.cut()

    def Copy(self):
        self.text.copy()

    def Paste(self):
        self.text.paste()


def main():
    app = QApplication(sys.argv)
    editor = XMLEditor()
    editor.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
