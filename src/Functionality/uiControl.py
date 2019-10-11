#! /usr/bin/env python3.

import os
import sys
import subprocess
import xml.etree.ElementTree as ET

from PyQt5 import QtWidgets
from PyQt5.QtCore import QEvent
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from src.GUI.python_files.BATT5_GUI import Ui_BATT5
from src.GUI.python_files.popups.errors import ErrFile, Errx86, ErrRadare
from src.GUI.python_files.popups.newProjectWind import NewProject
from src.GUI.python_files.popups.xmlEditor import XMLEditor
from src.GUI.python_files.popups.analysisResultView import Analysis_Window
from src.GUI.python_files.popups.documentationView import Documentation_Window
from src.GUI.python_files.popups.outputFieldView import OutputWindow


static = False
dynamic = False


class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()
        self.window = Ui_BATT5()
        self.window.setupUi(self)

        # ---- Main Window ---------------------------------
        self.setProject()
        self.window.projectNavigator_tree.itemSelectionChanged.connect(self.setProject)

        # ---- Menu Bar ------------------------------------

        # Clicking on New.. menu bar calls showNewProject method
        self.window.actionNew_Project.setShortcut("Ctrl+N")
        self.window.actionNew_Project.triggered.connect(self.showNewProject)

        # Clicking on Open.. menu bar calls showFileExplorer method
        self.window.actionOpen.setShortcut("Ctrl+O")
        self.window.actionOpen.triggered.connect(self.showFileExplorerSimple)

        # Clicking on Save.. menu bar call Save method
        self.window.actionSave.setShortcut("Ctrl+S")
        self.window.actionSave.triggered.connect(self.Save)

        # Clicking on Save As.. menu bar calls SaveAs method
        self.window.actionSave_as.setShortcut("Ctrl+Shift+S")
        self.window.actionSave_as.triggered.connect(self.SaveAs)

        # Clicking on Save Analysis.. menu bar calls showAnalysisWindow method
        self.window.actionSave_Analysis.setShortcut("Ctrl+S+A")
        self.window.actionSave_Analysis.triggered.connect(self.showAnalysisWindow)

        # Clicking on Windows menu bar calls..

        # Clicking on Help menu bar calls showDocumentWindow method
        self.window.actionDocumentation.triggered.connect(self.showDocumentationWindow)

        # ---- Analysis Tab ---------------------------------

        # Clicking will clear the comment box text
        self.window.commentClear_button.clicked.connect(self.Clear)

        # ---- Plugin Controls -----------------------------

        # Clicking on Generate Script button calls showOutputWindow method
        self.window.generateScript_button.clicked.connect(self.showOutputWindow)

        # Clicking on Run Static Analysis button calls runStatic method
        self.window.runStaticAnalysis_button.clicked.connect(self.runStatic)

        # Clicking on Run Static Analysis button calls runDynamic method
        self.window.runDynamicAnalysis_button.clicked.connect(self.runDynamic)

        # ---- Management Tab -------------------------------

        # Clicking on Plugin Structure browse button calls showFileExplorer method
        self.window.dpmPluginStructure_button.clicked.connect(self.showFileExplorer)

        # Clicking on Plugin Predefined browse button calls showFileExplorer method (xmlEditor for now)
        self.window.dpmPluginPredefined_button.clicked.connect(self.showFileExplorer2)

        # ---- Select listener ------------------------------

        self.window.projectProperties_text.installEventFilter(self)
        self.window.projectSearch_lineEdit.installEventFilter(self)
        self.window.projectNavigator_tree.installEventFilter(self)
        self.window.analysis_text.installEventFilter(self)
        self.window.radareConsole_text.installEventFilter(self)
        self.window.poi_list.installEventFilter(self)
        self.window.comment_text.installEventFilter(self)

        # ----- Radare Integration --------------------------

        # HArd code static analysis box with a path and poi...will grab this later from GUI
        # results = staticAnalysis("C:\Windows\System32\smss.exe", "fj")  # passes path, fj for functions for now
        # for i in range(len(results)):
        #     self.window.analysis_list.addItem(json.dumps(results[i]))  # puts each dictonary into a string then into the list widget

    # Used for letting the user know where they are typing
    def eventFilter(self, obj, event):
        global focus
        if event.type() == QEvent.FocusIn:
            if obj == self.window.projectSearch_lineEdit:
                self.window.projectSearch_lineEdit.clear()
                self.window.projectSearch_lineEdit.setStyleSheet("color: black;")
            else:
                self.window.projectSearch_lineEdit.setStyleSheet("color: rgb(136, 138, 133);")
                self.window.projectSearch_lineEdit.setText("Search..")

        return super(ApplicationWindow, self).eventFilter(obj, event)

    # Changes the project description according to the current project
    def setProject(self):
        selected = self.window.projectNavigator_tree.selectedItems()
        cur_path = os.getcwd()

        file = ''
        if selected:
            item = selected[0].text(0)
            item = item.split(" ")
            try:
                item = item[0] + item[1]
                file = os.path.join(cur_path, '..', 'Configurations', item + '.xml')
            except IndexError or FileNotFoundError:
                pass
        else:
            file = os.path.join(cur_path, '..', 'Configurations', 'project1.xml')

        if file:
            tree = ET.parse(file)
            root = tree.getroot()

            text = "<font size=2> <b>Project Description</b>: " \
                   "This is a description of the project that is currently selected. <br><br>"
            text += "<b>Project Properties</b>: <br> </font> "

            for child in root.iter():
                if child.tag != "Project" and child.get('name') is not None:
                    text += "<font size=2> <b>" + child.tag + "</b>" + ": " + child.get('name') + "<br> </font>"
            self.window.projectProperties_text.setHtml(text)

    # Opens up an xml (file) editor
    def xmlEditor(self):
        self.window = XMLEditor()
        self.window.show()

   # runs Static Analysis
    def runStatic(self):
        global static
        static = True
        self.window.runDynamicAnalysis_button.setStyleSheet("background-color:;")
        self.window.runDynamicAnalysis_button.setStyleSheet("color:;")

    # runs Dynamic Analysis
    def runDynamic(self):
        global static
        global dynamic
        if static is False:
            pass
        elif dynamic is False:
            dynamic = True
            self.window.runDynamicAnalysis_button.setText("Stop")
        else:
            dynamic = False
            self.window.runDynamicAnalysis_button.setText("Run Static Analysis")

    # Shows NewProject window
    def showNewProject(self):
        self.windowNP = QtWidgets.QWidget()
        self.ui = NewProject()
        self.ui.setupUi(self.windowNP)
        self.windowNP.show()

    # Shows Analysis Result window
    def showAnalysisWindow(self):
        self.windowAR = QtWidgets.QWidget()
        self.ui = Analysis_Window()
        self.ui.setupUi(self.windowAR)
        self.windowAR.show()


    # Shows Documentation window
    def showDocumentationWindow(self):
        self.windowDC = QtWidgets.QDialog()
        self.ui = Documentation_Window()
        self.ui.setupUi(self.windowDC)
        self.windowDC.show()

    # Shows Output window
    def showOutputWindow(self):
        self.windowOUT = QtWidgets.QWidget()
        self.ui = OutputWindow()
        self.ui.setupUi(self.windowOUT)
        self.windowOUT.show()

    # Shows ErrFile window
    def showErrFile(self):
        self.windowEF = ErrFile()
        self.windowEF.show()

    # Shows Errx86 window
    def showErrx86(self):
        self.windowE86 = Errx86()
        self.windowE86.show()

    # Shows ErrRadare window
    def showErrRadare(self):
        self.windowER = ErrRadare()
        self.windowER.show()

    # Open up file explorer to select a file
    def showFileExplorer(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmPluginStructure_lineEdit.setText(name)

    # Open up file explorer to select a file for Project Predefined line edit
    def showFileExplorer2(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmPluginPredefined_lineEdit.setText(name)

    # Open up file explorer, does not pass any data
    def showFileExplorerSimple(self):
        _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')

    # Will save the current modifications of the file
    def Save(self):
        cur_path = os.getcwd()
        name = os.path.join(cur_path, '..', 'Configurations', 'random.txt')    # TODO: Get correct file to Save
        try:
            file = open(name, 'w')
            text = self.window.projectProperties_text.toPlainText()
            file.write(text)
            file.close()
        except FileNotFoundError or AttributeError:
            pass

    # Will allow the user to change the name of the file and saves the current modifications of it
    def SaveAs(self):
        name, _ = QFileDialog.getSaveFileName(self, 'Save File', options=QFileDialog.DontUseNativeDialog)

        try:
            file = open(name, 'w')
            text = self.window.projectProperties_text.toPlainText()
            file.write(text)
            file.close()
        except FileNotFoundError:
            pass

    # Clear comment text
    def Clear(self):
        self.window.comment_text.clear()


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
