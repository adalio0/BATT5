import sys

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox

from src.GUI.python_files.popups.documentationView import Documentation_Window
from src.GUI.python_files.popups.errors import ErrEmptyFields


class DocumentationWindow(QtWidgets.QDialog):
    def __init__(self):
        super(DocumentationWindow, self).__init__()
        self.window = Documentation_Window()
        self.window.setupUi(self)

    # ---- Extracts file location -----------------------------------------------------------------------

    def showFileExplorer(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Browse", "",
                                                        "All Files (*);;Python Files (*.py)", options=options)

    # ---- Show Error Message ------------------------------------------

    def showErr(self):
        # self.windowEF = ErrEmptyFields()
        # self.windowEF.show()
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
