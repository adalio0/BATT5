import sys
from pathlib import Path

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox

from src.GUI.python_files.popups.newProjectWindow import NewProjectWindow
from src.Functionality.Analysis.binaryValidation import get_binary_info
from src.Database.database import insertToDatabase
properties = []


class NewProjectWindowControl(QtWidgets.QDialog):
    def __init__(self):
        super(NewProjectWindowControl, self).__init__()
        self.window = NewProjectWindow()
        self.window.setupUi(self)
        self.window.path_lineEdit.setDisabled(True)

        # create button pressed
        self.window.create_button.clicked.connect(self.createProject)
        # browse button pressed
        self.window.browse_button.clicked.connect(self.showFileExplorer)
        # cancel button pressed
        self.window.cancel_button.clicked.connect(self.close)

    # ---- Extracts file location -----------------------------------------------------------------------
    def showFileExplorer(self):
        path = Path(__file__).parents[3].as_posix() + '/Configurations/Sample Configurations'
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Browse", path,
                                                        "All Files (*);;Python Files (*.py)", options=options)
        self.window.path_lineEdit.setText(name)
        if name:
            self.setProperties()

    # ---- Extracts text from fields and inserts them into the project database -----------------
    def createProject(self):
        if self.window.projectName_lineEdit.text() == "":
            self.showErr()
        elif self.window.projectDescription_textEdit.toPlainText() == "":
            self.showErr()
        elif self.window.path_lineEdit.text() == "":
            self.showErr()
        else:
            # Store new project into the database
            insertToDatabase(self.window.projectName_lineEdit.text(),
                             self.window.projectDescription_textEdit.toPlainText(), self.window.path_lineEdit.text(),
                             properties)

            # close window
            self.accept()
            self.close()

    def accept(self):
        super(NewProjectWindowControl, self).accept()

    # ---- Show Error Message ------------------------------------------
    def showErr(self):
        QMessageBox.question(self, "Error Message: Missing Fields",
                             "All fields must be filled to in order to create a Project",
                             QMessageBox.Ok)

    def showx86Err(self):
        QMessageBox.question(self, "Error Message: File Selected is not x86",
                             "Binary should be x86 architecture in order to create a project",
                             QMessageBox.Ok)

    # ----Validate Binary x86-------------------------------------------------------
    def validatex86(self, arch):
        if arch == "x86":
            return True

    # ---- Displays binary data in Tree Widget -------------------------------------
    def setProperties(self):
        fileProperties = get_binary_info(self.window.path_lineEdit.text())

        bin = fileProperties.get('bin', {})
        tree = self.window.properties_treeWidget

        try:
            if not self.validatex86(bin['arch']):
                self.window.path_lineEdit.clear()
                self.showx86Err()
                return
        except KeyError:
            self.window.path_lineEdit.clear()
            self.showx86Err()
            return

        # os
        item0 = tree.itemAt(0, 0)
        try:
            item0.setText(1, str(bin['os']))
            properties.append(str(bin['os']))
        except KeyError:
            item0.setText(1, "N/A")
            properties.append("N/A")

        # arch
        item1 = tree.itemBelow(item0)
        try:
            item1.setText(1, str(bin['arch']))
            properties.append(str(bin['arch']))
        except KeyError:
            item1.setText(1, "N/A")
            properties.append("N/A")

        # binary type
        item2 = tree.itemBelow(item1)
        try:
            item2.setText(1, str(bin['bintype']))
            properties.append(str(bin['bintype']))
        except KeyError:
            item2.setText(1, "N/A")
            properties.append("N/A")

        # machine
        item3 = tree.itemBelow(item2)
        try:
            item3.setText(1, str(bin['machine']))
            properties.append(str(bin['machine']))
        except KeyError:
            item3.setText(1, "N/A")
            properties.append("N/A")

        # class
        item4 = tree.itemBelow(item3)
        try:
            item4.setText(1, str(bin['class']))
            properties.append(str(bin['class']))
        except KeyError:
            item4.setText(1, "N/A")
            properties.append("N/A")

        # bits
        item5 = tree.itemBelow(item4)
        try:
            item5.setText(1, str(bin['bits']))
            properties.append(str(bin['bits']))
        except KeyError:
            item5.setText(1, "N/A")
            properties.append("N/A")

        # language
        item6 = tree.itemBelow(item5)
        try:
            item6.setText(1, str(bin['lang']))
            properties.append(str(bin['lang']))
        except KeyError:
            item6.setText(1, "N/A")
            properties.append("N/A")

        # canary
        item7 = tree.itemBelow(item6)
        try:
            item7.setText(1, str(bin['canary']))
            properties.append(str(bin['canary']))
        except KeyError:
            item7.setText(1, "N/A")
            properties.append("N/A")

        # crypto
        item8 = tree.itemBelow(item7)
        try:
            item8.setText(1, str(bin['crypto']))
            properties.append(str(bin['crypto']))
        except KeyError:
            item8.setText(1, "N/A")
            properties.append("N/A")

        # nx
        item9 = tree.itemBelow(item8)
        try:
            item9.setText(1, str(bin['nx']))
            properties.append(str(bin['nx']))
        except KeyError:
            item9.setText(1, "N/A")
            properties.append("N/A")

        # pic
        item10 = tree.itemBelow(item9)
        try:
            item10.setText(1, str(bin['pic']))
            properties.append(str(bin['pic']))
        except KeyError:
            item10.setText(1, "N/A")
            properties.append("N/A")

        # relocs
        item11 = tree.itemBelow(item10)
        try:
            item11.setText(1, str(bin['relocs']))
            properties.append(str(bin['relocs']))
        except KeyError:
            item11.setText(1, "N/A")
            properties.append("N/A")

        # relro
        item12 = tree.itemBelow(item11)
        try:
            item12.setText(1, str(bin['relro']))
            properties.append(str(bin['relro']))
        except KeyError:
            item12.setText(1, "N/A")
            properties.append("N/A")

        # stripped
        item13 = tree.itemBelow(item12)
        try:
            item13.setText(1, str(bin['stripped']))
            properties.append(str(bin['stripped']))
        except KeyError:
            item13.setText(1, "N/A")
            properties.append("N/A")


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = NewProjectWindowControl()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
