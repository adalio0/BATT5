import sys

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QTreeWidgetItem
from numpy import unicode

from src.Functionality.project import Project
from src.GUI.python_files.popups.newProjectWind import NewProject
from src.GUI.python_files.popups.errors import ErrEmptyFields

project = Project


class ProjectWindow(QtWidgets.QDialog):
    def __init__(self):
        super(ProjectWindow, self).__init__()
        self.window = NewProject()
        self.window.setupUi(self)

        # create button pressed
        self.window.create_button.clicked.connect(self.createProject)
        # browse button pressed
        self.window.browse_button.clicked.connect(self.showFileExplorer)
        # cancel button pressed
        self.window.cancel_button.clicked.connect(self.close)

    # ---- Extracts File Location -----------------------------------------------------------------------
    def showFileExplorer(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.path_lineEdit.setText(name)
        self.setProperties()

    # ---- Extracts Text From Fields and Assigns Them To Project Object ---------------------------------
    def createProject(self):
        if self.window.projectName_lineEdit.text() == "":
            self.showErr()
        elif self.window.projectDescription_textEdit.toPlainText() == "":
            self.showErr()
        elif self.window.path_lineEdit.text() == "":
            self.showErr()
        else:
            # Set Name
            global project
            name = self.window.projectName_lineEdit.text()
            project.set_name(self, name)
            # Set Description
            description = self.window.projectDescription_textEdit.toPlainText()
            project.set_description(self, description)
            # select file
            file = self.window.path_lineEdit.text()
            project.set_file(self, file)
            # close window
            self.accept()
            self.close()

    def accept(self):
        self.obj = project
        super(ProjectWindow, self).accept()

    def getProject(self):
        return self.obj

    # ---- Show Error Message ---------------------------------
    def showErr(self):
        self.windowEF = ErrEmptyFields()
        self.windowEF.show()

    # ---- Sets Data To Project Object and Displays it in Tree Widget -------------------------------------
    def setProperties(self):
        global project
        project.set_os(self, "some os data")
        project.set_binary_type(self, "some binary data")
        project.set_machine(self, "some machine data")
        project.set_class(self, "some class data")
        project.set_bits(self, "some bit data")
        project.set_language(self, "some language data")
        project.set_new_item(self, "some new item data")
        project.set_canary(self, "some canary data")
        project.set_crypto(self, "some crypto data")
        project.set_nx(self, "some nx data")
        project.set_pic(self, "some pic data")
        project.set_relocs(self, "some relocs data")
        project.set_relro(self, "some relro data")
        project.set_stripped(self, "some stripped data")

        tree = self.window.properties_treeWidget
        properties = []
        # os
        item0 = tree.itemAt(0, 0)
        item0.setText(1, project.get_os(self))
        # binary type
        item1 = tree.itemBelow(item0)
        item1.setText(1, project.get_binary_type(self))
        # machine
        item2 = tree.itemBelow(item1)
        item2.setText(1, project.get_machine(self))
        # class
        item3 = tree.itemBelow(item2)
        item3.setText(1, project.get_class(self))
        # bits
        item4 = tree.itemBelow(item3)
        item4.setText(1, project.get_bits(self))
        # language
        item5 = tree.itemBelow(item4)
        item5.setText(1, project.get_language(self))
        # new item
        item6 = tree.itemBelow(item5)
        item6.setText(1, project.get_new_item(self))
        # canary
        item7 = tree.itemBelow(item6)
        item7.setText(1, project.get_canary(self))
        # crypto
        item8 = tree.itemBelow(item7)
        item8.setText(1, project.get_crypto(self))
        # nx
        item9 = tree.itemBelow(item8)
        item9.setText(1, project.get_nx(self))
        # pic
        item10 = tree.itemBelow(item9)
        item10.setText(1, project.get_pic(self))
        # relocs
        item11 = tree.itemBelow(item10)
        item11.setText(1, project.get_relocs(self))
        # relro
        item12 = tree.itemBelow(item11)
        item12.setText(1, project.get_relro(self))
        # stripped
        item13 = tree.itemBelow(item12)
        item13.setText(1, project.get_stripped(self))


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ProjectWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
