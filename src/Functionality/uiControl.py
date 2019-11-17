#! /usr/bin/env python3.

import os
import sys
from pathlib import Path

# sys.path.insert(0, Path(__file__).parents[2].as_posix())
# sys.path.insert(0, "/mnt/c/Users/jgauc/PycharmProjects/BATT5/src")
# sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt5 import QtWidgets
from PyQt5.QtCore import QEvent

from src.GUI.python_files.BATT5_GUI import Ui_BATT5
from src.GUI.python_files.popups.errors import ErrFile, Errx86, ErrRadare
from src.Functionality.newProject import ProjectWindow
from src.Functionality.newOutput import NOutputWindow
from src.GUI.python_files.popups.analysisResultView import Analysis_Window
from src.GUI.python_files.popups.documentationView import Documentation_Window
from src.Functionality.staticAnalysis import staticAnalysis
from src.Functionality.radareTerminal import Terminal
from src.Functionality.poiManagement import *
from src.Functionality.pluginManagement import *
from src.Functionality.database import *
from src.Functionality.search import *
from src.Functionality.dynamicAnalysis import dynamicAnalysis

allpoiTypeCheck = False


class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()
        self.window = Ui_BATT5()
        self.window.setupUi(self)

    # ---- Main Window --------------------------------------------------------------------------------------------
        # Populate the projects box with current projects
        self.populateProjectBox()

        # Populate the management plugin boxes with the current plugins
        self.populatePluginFields()

        # Populate the management poi list with poi from plugin
        # self.populatePoiFromPlugin()

        # Initialize the project properties and Terminal
        self.setProject()

        self.checkUncheckAllPlugins()

    # ---- Menu Bar -----------------------------------------------------------------------------------------------
        # Clicking on New.. menu bar calls showNewProject method
        self.window.actionNew_Project.setShortcut("Ctrl+N")
        self.window.actionNew_Project.triggered.connect(self.showNewProject)

        # Clicking on Open.. menu bar calls showFileExplorer method
        self.window.actionOpen.setShortcut("Ctrl+O")
        # self.window.actionOpen.triggered.connect(self.showFileExplorerSimple)

        # Clicking on Save.. menu bar call Save method
        self.window.actionSave.setShortcut("Ctrl+S")
        self.window.actionSave.triggered.connect(self.Save)

        # Clicking on Save As.. menu bar calls SaveAs method
        self.window.actionSave_as.setShortcut("Ctrl+Shift+S")
        self.window.actionSave_as.triggered.connect(self.SaveAs)

        # Clicking on Save Analysis.. menu bar calls showAnalysisWindow method
        self.window.actionSave_Analysis.setShortcut("Ctrl+alt+S")
        self.window.actionSave_Analysis.triggered.connect(self.showAnalysisWindow)

        # Clicking on Windows menu bar calls..

        # Clicking on Help menu bar calls showDocumentWindow method
        self.window.actionDocumentation.triggered.connect(self.showDocumentationWindow)

    # ---- Analysis Tab --------------------------------------------------------------------------------------------
        # Clicking on the save button near the comment box will save the comment in the selected poi
        self.window.commentSave_button.clicked.connect(self.callSaveComment)

        # Clicking will clear button near the comment box will clear the comment box text
        self.window.commentClear_button.clicked.connect(self.clearComment)

        # When clicking a Project in the project box, the project properties will update to the selected project
        self.window.projectNavigator_tree.itemSelectionChanged.connect(self.setProject)

        # right click functionality for projects
        self.window.projectNavigator_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.window.projectNavigator_tree.customContextMenuRequested.connect(self.rightClickOnProject)

        # Clicking on Run Static Analysis button calls runStatic method
        self.window.runStaticAnalysis_button.clicked.connect(self.runStatic)

        # Clicking on Run Dynamic Analysis button calls runDynamic method
        self.window.runDynamicAnalysis_button.clicked.connect(self.runDynamic)

    # ---- Search Functions ----------------------------------------------------------------------------------------
        # returns the searched elements in the project list
        self.window.projectSearch_lineEdit.returnPressed.connect(self.callSearchProject)

        # returns the searched elements in the poi list
        self.window.poiSearch_lineEdit.returnPressed.connect(self.callSearchPoi)

        # returns the searched elements in the plugin list
        self.window.pluginManagementSearch_lineEdit.returnPressed.connect(self.callSearchPluginM)

        # returns the searched elements in the poi list
        self.window.poiManagementSeach_lineEdit.returnPressed.connect(self.callSearchPoiM)

    # ---- Comment Functionality ----------------------------------------------------------------------------------
        self.window.poi_list.currentItemChanged.connect(self.callHighlightTable)

        self.window.POI_tableWidget.currentItemChanged.connect(self.callHighlightList)

    # ---- Filters ------------------------------------------------------------------------------------------------
        # When changing POI type in the drop down will update whats displayed
        self.window.poiType_dropdown.currentIndexChanged.connect(self.displayPoi)

    # ---- Console ------------------------------------------------------------------------------------------------
        # Executes the input command in the radare prompt
        self.window.radareConsoleIn_lineEdit.returnPressed.connect(self.inputCommand)

    # ---- Plugin Controls ----------------------------------------------------------------------------------------
        # Clicking on Generate Script button calls showOutputWindow method
        self.window.generateScript_button.clicked.connect(self.showOutputWindow)

    # ---- Management Tab -----------------------------------------------------------------------------------------
        # Clicking on Plugin Structure browse button calls showFileExplorer method
        self.window.dpmPluginStructure_button.clicked.connect(self.showFileExplorer)

        # Clicking on browse plugin function output source
        self.window.dpmOutFuncSource_button.clicked.connect(self.showFileExplorer_outFuncSource)

        # Creating new plugin from xml
        self.window.saveXMLPlugin_button.clicked.connect(self.callSavePluginXML)

        # Creating a new plugin from manual
        self.window.saveManualPlugin_button.clicked.connect(self.callSavePluginManual)

        # Clicking on Plugin Predefined browse button calls showFileExplorer method
        self.window.dpoimPredefined_button.clicked.connect(self.showFileExplorer_predefined)

        # Clicking on a plugin inside the list will show a detailed view of it
        self.window.pluginManagement_list.itemClicked.connect(self.displayPlugin)

        # Clicking on the clear button below the management plugin box will allow user to create new plugin
        self.window.clearManualPlugin_button.clicked.connect(self.newManualPluginTemplate)

        # Clicking on the clear button in Add Plugin Through Manual Input will clear the text
        self.window.clearXMLPlugin_button.clicked.connect(self.newXMLPluginTemplate)

        # check or uncheck all elements in poi list
        self.window.checkAllPlugins_checkBox.stateChanged.connect(self.checkUncheckAllPlugins)

        # Right clicking on a plugin in the management plugin box will bring up confirmation for deleting
        self.window.pluginManagement_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.window.pluginManagement_list.customContextMenuRequested.connect(self.rightClickOnPlugin)

        # Clicking on a poi inside the list will show a detailed view of it
        # self.window.poiManagement_list.itemClicked.connect(self.displayPoiFromPlugin)

        # Clicking on the new button below the management poi box will allow user to create new poi
        self.window.clearPoiAll_button.clicked.connect(self.newManualPoiTemplate)

        self.window.clearPredefPoi_button.clicked.connect(self.newXMLPoiTemplate)

        # Clicking on the delete button while a poi is selected on the management poi list will delete it
        # self.window.dpoimDelete_button.clicked.connect(self.callDeletePoiFromPlugin)

    # ---- View Box -----------------------------------------------------------------------------------------------
        self.window.switchToHistory_button.clicked.connect(self.switchToHistory)
        self.window.switchToCurrent_button.clicked.connect(self.switchToCurrent)

    # ---- Other? -------------------------------------------------------------------------------------------------
        # check or uncheck all elements in poi list
        self.window.check_allpoi.stateChanged.connect(self.checkstate_poi)

# TODO---- Following methods initialize the main window with all the project, plugin and poi data -------------------

    # Initialize the project box with all the current projects from database
    def populateProjectBox(self):
        projects = getProjects()
        projectTree = []
        for i in range(len(projects)):
            projectTree.append(QTreeWidgetItem([projects[i]]))
        tree = self.window.projectNavigator_tree
        tree.addTopLevelItems(projectTree)

    # Changes the project description according to the current project from database
    def setProject(self):
        selected = self.window.projectNavigator_tree.selectedItems()

        text, binaryPath = setCurrentProject(selected)
        self.setWindowTitle(setWindowTitle())

        # Populate the properties box with the current project
        self.window.projectProperties_text.setHtml(text)

        # Checks if static has already been performed, if so unlock dynamic and display poi
        if checkStatic():
            self.window.runDynamicAnalysis_button.setEnabled(True)
            self.window.runDynamicAnalysis_button.setStyleSheet("background-color:;")
            self.window.runDynamicAnalysis_button.setStyleSheet("color:;")
            self.displayPoi()
        else:
            self.window.runDynamicAnalysis_button.setEnabled(False)
            self.window.runDynamicAnalysis_button.setStyleSheet("background-color: rgb(186, 189, 182);")
            self.window.runDynamicAnalysis_button.setStyleSheet("color: rgb(136, 138, 133);")
            self.window.POI_tableWidget.clear()
            self.window.POI_tableWidget.setRowCount(0)
            self.window.POI_tableWidget.setColumnCount(0)
            self.window.poi_list.clear()

        # Set up command prompt
        self.terminal = Terminal(binaryPath, self.window.radareConsoleIn_lineEdit, self.window.radareConsoleOut_text)

    # Initialize every field that involve plugins with all the current plugins from database
    def populatePluginFields(self):
        plugins = getPlugins()

        # plugin management list
        self.window.pluginManagement_list.clear()
        self.window.pluginManagement_list.addItems(plugins)

        # add to plugin list
        self.window.addToPlugin_list.clear()
        self.window.addToPlugin_list.addItems(plugins)
        self.checkUncheckAllPlugins()

        # plugin dropdown menu
        self.window.pluginSelection_dropdown.clear()
        self.window.pluginSelection_dropdown.addItem('None')  # TEMP LINE
        self.window.pluginSelection_dropdown.addItems(plugins)

# TODO---- The following methods are performed in the analysis tab of the BATT5 system ------------------------------

    # ---- Following methods provide all the search functionality in the analysis tab --------------------------

    # Search functionality for the project box
    def callSearchProject(self):
        try:
            searchProject(str(self.window.projectSearch_lineEdit.text()), self.window.projectNavigator_tree)
            if not self.window.projectSearch_lineEdit.text():
                self.populateProjectBox()
        except AttributeError:
            pass

    # Search functionality for the poi box
    def callSearchPoi(self):
        try:
            searchPoi(str(self.window.poiSearch_lineEdit.text()), self.window.poi_list)
            if not self.window.poiSearch_lineEdit.text():
                self.displayPoi()
        except AttributeError:
            pass

    # ---- Following methods are vital for everything revolving static analysis -------------------------------

    # runs Static Analysis w/ database stuff
    def runStatic(self):
        if not checkStatic():
            self.window.runDynamicAnalysis_button.setEnabled(True)
            self.window.runDynamicAnalysis_button.setStyleSheet("background-color:;")
            self.window.runDynamicAnalysis_button.setStyleSheet("color:;")

            # Get the path of the binary file and run static analysis
            path = getCurrentFilePath()
            poi = staticAnalysis(path)

            # Save the results of static into the database
            saveStatic(poi)
            self.displayPoi()
        else:
            self.displayPoi()

    # Displays POIs in the Analysis box
    def displayPoi(self):
        self.window.POI_tableWidget.clear()
        self.window.poi_list.clear()
        poi = str(self.window.poiType_dropdown.currentText())
        content = getPoi(poi)
        filterContent = getFilterPoi(self.window.pluginSelection_dropdown.currentText())

        # Call appropriate method to display poi
        if poi == 'Function':
            self.enableCheck()
            if self.window.pluginSelection_dropdown.currentText() == 'None':
                self.displayFunctions(content)
            else:
                self.displayFilteredFunctions(filterContent, content)
        else:
            self.disableCheck()
            if poi == 'String':
                if self.window.pluginSelection_dropdown.currentText() == 'None':
                    self.displayString(content)
                else:
                    self.displayFilterStrings(filterContent, content)
            elif poi == 'Variable':
                if self.window.pluginSelection_dropdown.currentText() == 'None':
                    self.displayVariable(content)
                else:
                    self.displayFilteredVariable(filterContent, content)
            elif poi == 'DLL':
                if self.window.pluginSelection_dropdown.currentText() == 'None':
                    self.displayDll(content)
                else:
                    self.displayFilteredDll(filterContent, content)
            elif poi == 'Struct':
                if self.window.pluginSelection_dropdown.currentText() == 'None':
                    self.displayStruct(content)

    # Displays the functions extracted from Static Analysis in Analysis box and POI box
    def displayFunctions(self, content):
        self.window.POI_tableWidget.setColumnCount(6)
        self.window.POI_tableWidget.setHorizontalHeaderLabels(['offset', 'name', 'size', 'Ncallrefs', 'Nspvars', 'Nregvars'])
        self.window.POI_tableWidget.setRowCount(len(content))
        for i in range(len(content)):
            if 'offset' in content[i]:
                self.window.POI_tableWidget.setItem(i, 0, QTableWidgetItem(str(content[i]['offset'])))
            if 'name' in content[i]:
                tableItem = QTableWidgetItem(content[i]['name'])
                if getComment(content[i]['name'], "Function", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 1, tableItem)
            if 'size' in content[i]:
                self.window.POI_tableWidget.setItem(i, 2, QTableWidgetItem(str(content[i]['size'])))
            if 'callrefs' in content[i]:
                self.window.POI_tableWidget.setItem(i, 3, QTableWidgetItem(str(len(content[i]['callrefs']))))
            if 'spvars' in content[i]:
                self.window.POI_tableWidget.setItem(i, 4, QTableWidgetItem(str(len(content[i]['spvars']))))
            if 'regvars' in content[i]:
                self.window.POI_tableWidget.setItem(i, 5, QTableWidgetItem(str(len(content[i]['regvars']))))

            item = QListWidgetItem(content[i]['name'])
            # set icon
            if getComment(content[i]['name'], "Function", self.window.comment_text):
                addIcon(item)
            item.setCheckState(QtCore.Qt.Checked)
            self.window.poi_list.addItem(item)

    # Displays the filtered functions based on the selected plugin in Analysis box and POI box
    def displayFilteredFunctions(self, filterContent, content):
        self.window.POI_tableWidget.setColumnCount(6)
        self.window.POI_tableWidget.setHorizontalHeaderLabels(['offset', 'name', 'size', 'Ncallrefs', 'Nspvars', 'Nregvars'])
        self.window.POI_tableWidget.setRowCount(len(filterContent['function']))
        for j in range(len(filterContent['function'])):
            for i in range(len(content)):
                if content[i]['name'] in filterContent['function'][j]['name']:
                    if 'offset' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 0, QTableWidgetItem(str(content[i]['offset'])))
                    if 'name' in content[i]:
                        tableItem = QTableWidgetItem(content[i]['name'])
                        if getComment(content[i]['name'], "Function", self.window.comment_text):
                            highlightCell(tableItem)
                        self.window.POI_tableWidget.setItem(j, 1, tableItem)
                    if 'size' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 2, QTableWidgetItem(str(content[i]['size'])))
                    if 'callrefs' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 3, QTableWidgetItem(str(len(content[i]['callrefs']))))
                    if 'spvars' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 4, QTableWidgetItem(str(len(content[i]['spvars']))))
                    if 'regvars' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 5, QTableWidgetItem(str(len(content[i]['regvars']))))

                    item = QListWidgetItem(content[i]['name'])
                    # set icon
                    if getComment(content[i]['name'], "Function", self.window.comment_text):
                        addIcon(item)
                    item.setCheckState(QtCore.Qt.Checked)
                    self.window.poi_list.addItem(item)

    # Displays the strings extracted from Static Analysis in Analysis box and POI box
    def displayString(self, content):
        self.window.POI_tableWidget.setColumnCount(5)
        self.window.POI_tableWidget.setHorizontalHeaderLabels(['type', 'size', 'length', 'section', 'string'])
        self.window.POI_tableWidget.setRowCount(len(content))
        for i in range(len(content)):
            if 'type' in content[i]:
                self.window.POI_tableWidget.setItem(i, 0, QTableWidgetItem(content[i]['type']))
            if 'size' in content[i]:
                self.window.POI_tableWidget.setItem(i, 1, QTableWidgetItem(str(content[i]['size'])))
            if 'length' in content[i]:
                self.window.POI_tableWidget.setItem(i, 2, QTableWidgetItem(str(content[i]['length'])))
            if 'section' in content[i]:
                self.window.POI_tableWidget.setItem(i, 3, QTableWidgetItem(str(content[i]['section'])))
            if 'string' in content[i]:
                tableItem = QTableWidgetItem(content[i]['string'])
                if getComment(content[i]['string'], "String", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 4, tableItem)
            item = QListWidgetItem(content[i]['string'])
            # set icon
            if getComment(content[i]['string'], "String", self.window.comment_text):
                addIcon(item)
            self.window.poi_list.addItem(item)

    # Displays the filtered strings based on the selected plugin in Analysis box and POI box
    def displayFilterStrings(self, filterContent, content):
        self.window.POI_tableWidget.setColumnCount(5)
        self.window.POI_tableWidget.setHorizontalHeaderLabels(['type', 'size', 'length', 'section', 'string'])
        self.window.POI_tableWidget.setRowCount(len(filterContent['string']))
        for j in range(len(filterContent['string'])):
            for i in range(len(content)):
                if content[i]['string'] in filterContent['string'][j]['name']:
                    if 'type' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 0, QTableWidgetItem(content[i]['type']))
                    if 'size' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 1, QTableWidgetItem(str(content[i]['size'])))
                    if 'length' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 2, QTableWidgetItem(str(content[i]['length'])))
                    if 'section' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 3, QTableWidgetItem(str(content[i]['section'])))
                    if 'string' in content[i]:
                        tableItem = QTableWidgetItem(content[i]['string'])
                        if getComment(content[i]['string'], "String", self.window.comment_text):
                            highlightCell(tableItem)
                        self.window.POI_tableWidget.setItem(j, 4, tableItem)

                    item = QListWidgetItem(content[i]['string'])
                    # set icon
                    if getComment(content[i]['string'], "String", self.window.comment_text):
                        addIcon(item)
                    self.window.poi_list.addItem(item)

    # Displays the variables extracted from Static Analysis in Analysis box and POI box
    def displayVariable(self, content):
        self.window.POI_tableWidget.setColumnCount(5)
        self.window.POI_tableWidget.setHorizontalHeaderLabels(['name', 'kind', 'type', 'base', 'offset'])
        self.window.POI_tableWidget.setRowCount(len(content))
        for i in range(len(content)):
            if 'name' in content[i]:
                tableItem = QTableWidgetItem(content[i]['name'])
                if getComment(content[i]['name'], "Variable", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 0, tableItem)
            if 'kind' in content[i]:
                self.window.POI_tableWidget.setItem(i, 1, QTableWidgetItem(content[i]['kind']))
            if 'type' in content[i]:
                self.window.POI_tableWidget.setItem(i, 2, QTableWidgetItem(content[i]['type']))
            if 'offset' in content[i]['ref']:
                self.window.POI_tableWidget.setItem(i, 3, QTableWidgetItem(content[i]['ref']['base']))
            if 'offset' in content[i]['ref']:
                self.window.POI_tableWidget.setItem(i, 4, QTableWidgetItem(content[i]['ref']['offset']))

            item = QListWidgetItem(content[i]['name'])
            # set icon
            if getComment(content[i]['name'], "Variable", self.window.comment_text):
                addIcon(item)
            self.window.poi_list.addItem(item)

    # Displays the filtered variables based on the selected plugin in Analysis box and POI box
    def displayFilteredVariable(self, filterContent, content):
        self.window.POI_tableWidget.setColumnCount(5)
        self.window.POI_tableWidget.setHorizontalHeaderLabels(['name', 'kind', 'type', 'base', 'offset'])
        self.window.POI_tableWidget.setRowCount(len(filterContent['variable']))
        for j in range(len(filterContent['variable'])):
            for i in range(len(content)):
                if content[i]['name'] in filterContent['variable'][j]['name']:
                    if 'name' in content[i]:
                        tableItem = QTableWidgetItem(content[i]['name'])
                        if getComment(content[i]['name'], "Variable", self.window.comment_text):
                            highlightCell(tableItem)
                        self.window.POI_tableWidget.setItem(j, 0, tableItem)
                    if 'kind' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 1, QTableWidgetItem(content[i]['kind']))
                    if 'type' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 2, QTableWidgetItem(content[i]['type']))
                    if 'offset' in content[i]['ref']:
                        self.window.POI_tableWidget.setItem(j, 3, QTableWidgetItem(content[i]['ref']['base']))
                    if 'offset' in content[i]['ref']:
                        self.window.POI_tableWidget.setItem(j, 4, QTableWidgetItem(content[i]['ref']['offset']))

                    item = QListWidgetItem(content[i]['name'])
                    # set icon
                    if getComment(content[i]['name'], "Variable", self.window.comment_text):
                        addIcon(item)
                    self.window.poi_list.addItem(item)

    # Displays the dlls extracted from Static Analysis in Analysis box and POI box
    def displayDll(self, content):
        self.window.POI_tableWidget.setColumnCount(4)
        self.window.POI_tableWidget.setHorizontalHeaderLabels(['name', 'type', 'bind', 'vaddr'])
        self.window.POI_tableWidget.setRowCount(len(content))
        for i in range(len(content)):
            if 'name' in content[i]:
                tableItem = QTableWidgetItem(content[i]['name'])
                if getComment(content[i]['name'], "DLL", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 0, tableItem)
            if 'type' in content[i]:
                self.window.POI_tableWidget.setItem(i, 1, QTableWidgetItem(content[i]['type']))
            if 'bind' in content[i]:
                self.window.POI_tableWidget.setItem(i, 2, QTableWidgetItem(content[i]['bind']))
            if 'vaddr' in content[i]:
                self.window.POI_tableWidget.setItem(i, 3, QTableWidgetItem(content[i]['vaddr']))

            item = QListWidgetItem(content[i]['name'])
            # set icon
            if getComment(content[i]['name'], "DLL", self.window.comment_text):
                addIcon(item)
            self.window.poi_list.addItem(item)

    # Displays the filtered dlls based on the selected plugin in Analysis box and POI box
    def displayFilteredDll(self, filterContent, content):
        self.window.POI_tableWidget.setColumnCount(4)
        self.window.POI_tableWidget.setHorizontalHeaderLabels(['name', 'type', 'bind', 'vaddr'])
        self.window.POI_tableWidget.setRowCount(len(filterContent['dll']))
        for j in range(len(filterContent['dll'])):
            for i in range(len(content)):
                if content[i]['name'] in filterContent['dll'][j]['name']:
                    if 'name' in content[i]:
                        tableItem = QTableWidgetItem(content[i]['name'])
                        if getComment(content[i]['name'], "DLL", self.window.comment_text):
                            highlightCell(tableItem)
                        self.window.POI_tableWidget.setItem(j, 0, tableItem)
                    if 'type' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 1, QTableWidgetItem(content[i]['type']))
                    if 'bind' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 2, QTableWidgetItem(content[i]['bind']))
                    if 'vaddr' in content[i]:
                        self.window.POI_tableWidget.setItem(j, 3, QTableWidgetItem(content[i]['vaddr']))

                    item = QListWidgetItem(content[i]['name'])
                    # set icon
                    if getComment(content[i]['name'], "DLL", self.window.comment_text):
                        addIcon(item)
                    self.window.poi_list.addItem(item)

    def displayStruct(self, content):
        self.window.POI_tableWidget.setHorizontalHeaderLabels(['name', 'size'])
        self.window.POI_tableWidget.setColumnCount(2)
        self.window.POI_tableWidget.setRowCount(len(content))
        for i in range(len(content)):
            if 'type' in content[i]:
                tableItem = QTableWidgetItem(content[i]['type'])
                if getComment(content[i]['type'], "Struct", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 0, tableItem)
            if 'size' in content[i]:
                self.window.POI_tableWidget.setItem(i, 1, QTableWidgetItem(str(content[i]['size'])))

            item = QListWidgetItem(content[i]['type'])
            self.window.poi_list.addItem(item)

    # ---- Following methods are vital for everything revolving dynamic analysis --------------------------------

    # Takes input from user and passes it to the terminal
    def inputCommand(self):
        cmd_in = str(self.window.radareConsoleIn_lineEdit.text())
        self.terminal.processInput(cmd_in)
        self.window.radareConsoleIn_lineEdit.clear()

    # runs Dynamic Analysis
    def runDynamic(self):
        if self.window.runDynamicAnalysis_button.text() == "Run Dynamic Analysis":
            self.window.runDynamicAnalysis_button.setText("Stop Dynamic Analysis")

            items = []
            for i in range(self.window.poi_list.count()):
                items.append(self.window.poi_list.item(i).text())
            # test by hardcoding two known functions
            items.append("sym.secret_stuff")
            items.append("sym.even_more_secret")

            path = getCurrentFilePath().strip()
            print(path)
            dynamic = dynamicAnalysis(path, items)
            # print(dynamic)
            # print(self.window.poi_list.item(i).text())
            for j in range(len(dynamic)):
                self.window.radareConsoleOut_text.append(dynamic[j])

        elif self.window.runDynamicAnalysis_button.text() == "Stop Dynamic Analysis":
            self.window.runDynamicAnalysis_button.setText("Run Dynamic Analysis")

    # ---- Following methods are for deleting a project from the database -------------------

    # Provides the functionality to delete a project by right clicking on it
    def rightClickOnProject(self, point):
        # Infos about the node selected.
        index = self.window.projectNavigator_tree.indexAt(point)

        if not index.isValid():
            return

        item = self.window.projectNavigator_tree.itemAt(point)
        name = item.text(0)  # The text of the node.

        # We build the menu.
        menu = QtWidgets.QMenu()

        menu.addAction("Delete", self.showConfirmationDeleteProject)

        menu.exec_(self.window.projectNavigator_tree.mapToGlobal(point))

    # Deletes a project
    def callDeleteProject(self):
        if self.window.projectNavigator_tree.currentItem():
            project = self.window.projectNavigator_tree.currentItem().text(0)
            deleteAProject(project)

            self.window.projectNavigator_tree.clear()
            self.populateProjectBox()

    # ---- Following methods are for calling and showing the different windows in the analysis tab ------------------

    # Shows NewProject window
    def showNewProject(self):
        self.ui = ProjectWindow()
        if self.ui.exec_() == ProjectWindow.Accepted:
            self.window.projectNavigator_tree.clear()
            self.populateProjectBox()

    # Shows confirmation to delete project
    def showConfirmationDeleteProject(self):
        self.callDeleteProject()

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
        self.ui = NOutputWindow()
        self.ui.show()

    # Open the file explorer to select a file for the output window
    def showFileExplorer_outFuncSource(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmOutFuncSource_lineEdit.setText(name)

    # ---- Following methods are for misc. stuff in the analysis tab ---------------------------------------

    # Will save the current modifications of the project
    def Save(self):
        print("Save")

    # Will allow the user to change the name of the file, saving the current modifications of it
    def SaveAs(self):
        print("Save As")

    # Save a comment in the currently clicked poi from the poi list
    def callSaveComment(self):
        saveComment(self.window.comment_text.toPlainText(), self.window.poi_list.currentItem().text(),
                    self.window.poiType_dropdown.currentText())
        addIcon(self.window.poi_list.currentItem())
        highlightCell(self.window.POI_tableWidget.currentItem())

    # Clear comment text
    def clearComment(self):
        self.window.comment_text.clear()

    # enable checkbox
    def enableCheck(self):
        self.window.check_allpoi.setCheckable(True)

    # disable checkbox
    def disableCheck(self):
        self.window.check_allpoi.setCheckable(False)

    # Check or Uncheck poi List
    def checkstate_poi(self):
        global allpoiTypeCheck
        if allpoiTypeCheck is True:
            for i in range(self.window.poi_list.count()):
                item = self.window.poi_list.item(i)
                if item.text() == "-----FUNCTIONS-----":
                    continue
                elif item.text() == "-----STRINGS-----":
                    break
                else:
                    if self.window.check_allpoi.isChecked():
                        item.setCheckState(QtCore.Qt.Checked)
                    elif self.window.check_allpoi.checkState() == 0:
                        item.setCheckState(QtCore.Qt.Unchecked)

        elif allpoiTypeCheck is False:
            if self.window.check_allpoi.isChecked():
                for i in range(self.window.poi_list.count()):
                    item = self.window.poi_list.item(i)
                    item.setCheckState(QtCore.Qt.Checked)

            elif self.window.check_allpoi.checkState() == 0:
                for i in range(self.window.poi_list.count()):
                    item = self.window.poi_list.item(i)
                    item.setCheckState(QtCore.Qt.Unchecked)

    # From current to history
    def switchToHistory(self):
        self.window.changeViews_stack.setCurrentIndex(1)

    def switchToCurrent(self):
        self.window.changeViews_stack.setCurrentIndex(0)

    def callHighlightTable(self):
        try:
            highlightTable(self.window.poi_list.currentItem().text(), self.window.POI_tableWidget)
            getComment(self.window.poi_list.currentItem().text(), self.window.poiType_dropdown.currentText(),
                       self.window.comment_text)
        except AttributeError:
            pass

    def callHighlightList(self):
        try:
            HighlightList(self.window.POI_tableWidget.currentItem().text(), self.window.poi_list)
        except AttributeError:
            pass

# TODO---- Following methods are performed in the management tab of the BATT5 system -------------------------------

    # ---- Following methods provide all the search functionality in the management tab --------------------------

    def callSearchPluginM(self):
        try:
            searchPluginM(str(self.window.pluginManagementSearch_lineEdit.text()), self.window.pluginManagement_list)
        except AttributeError:
            pass

    def callSearchPoiM(self):
        try:
            searchPoiM(str(self.window.poiManagementSeach_lineEdit.text()), self.window.poiManagement_list)
        except AttributeError:
            pass

    # ---- Following methods are for saving/creating a new plugin or poi based on predefined or manual input -------

    # Save a predefined plugin into the database
    def callSavePluginXML(self):
        savePluginXML(self.window.dpmPluginStructure_lineEdit)
        self.populatePluginFields()
        self.newXMLPluginTemplate()

    # Save a manually inputted plugin into the database
    def callSavePluginManual(self):
        savePluginManual(self.window.dpmPluginName_lineEdit, self.window.dpmPluginDesc_lineEdit,
                         self.window.dpmOutName_lineEdit, self.window.dpmOutFuncName_lineEdit,
                         self.window.dpmOutFuncSource_lineEdit)
        self.populatePluginFields()
        self.newManualPluginTemplate()

    # Clears the labels that are used for creating a new predefined plugin to create a new plugin
    def newXMLPluginTemplate(self):
        self.window.dpmPluginStructure_lineEdit.clear()
        self.window.pluginManagement_list.clearSelection()

    # Clears the labels that are used for creating a new plugin to create a new plugin
    def newManualPluginTemplate(self):
        self.window.dpmPluginName_lineEdit.clear()
        self.window.dpmPluginDesc_lineEdit.clear()
        self.window.dpmOutName_lineEdit.clear()
        self.window.dpmOutFuncName_lineEdit.clear()
        self.window.dpmOutFuncSource_lineEdit.clear()
        self.window.pluginManagement_list.clearSelection()

    # Clears the labels that are used for creating a new predefined poi set to create a new poi set
    def newXMLPoiTemplate(self):
        self.window.dpoimPredefined_lineEdit.clear()

    # Clears the labels that are used for creating a new predefined poi to create a new poi
    def newManualPoiTemplate(self):
        self.window.funcName_lineEdit.clear()
        self.window.strName_lineEdit.clear()
        self.window.varName_lineEdit.clear()
        self.window.dllName_lineEdit.clear()
        # self.window.protoName_lineEdit.clear()
        self.window.structName_lineEdit.clear()

    # ---- Following methods are for displaying detailed views of either a plugin or poi in the management tab -------

    # Displays a detailed view of a plugin when it is clicked
    def displayPlugin(self):
        item = self.window.pluginManagement_list.currentItem().text()
        name, description, poi, output = getCurrentPlugin(item)

        self.window.dpmPluginName_lineEdit.setText(name)
        self.window.dpmPluginDesc_lineEdit.setText(description)
        self.window.dpmOutName_lineEdit.setText(output['name'])
        self.window.dpmOutFuncName_lineEdit.setText(output['functionName'])
        self.window.dpmOutFuncSource_lineEdit.setText(output['functionSource'])

    # Displays a detailed view of a poi when it is clicked
    def displayPoiFromPlugin(self):
        if self.window.dpoimPlugin_dropdown.currentText():
            plugin = self.window.dpoimPlugin_dropdown.currentText()
            item = self.window.poiManagement_list.currentItem().text()

            info = getCurrentPluginInfo(plugin)
            for i in range(len(info['pointOfInterest']['function'])):
                if info['pointOfInterest']['function'][i]['name'] == item:
                    self.window.dpoimPoiType_dropdown.setCurrentIndex(1)
                    self.window.funcName_lineEdit.setText(item)

            for i in range(len(info['pointOfInterest']['string'])):
                if info['pointOfInterest']['string'][i]['name'] == item:
                    self.window.dpoimPoiType_dropdown.setCurrentIndex(2)
                    self.window.strName_lineEdit.setText(item)

            for i in range(len(info['pointOfInterest']['variable'])):
                if info['pointOfInterest']['variable'][i]['name'] == item:
                    self.window.dpoimPoiType_dropdown.setCurrentIndex(3)
                    self.window.varName_lineEdit.setText(item)

            for i in range(len(info['pointOfInterest']['dll'])):
                if info['pointOfInterest']['dll'][i]['name'] == item:
                    self.window.dpoimPoiType_dropdown.setCurrentIndex(4)
                    self.window.dllName_lineEdit.setText(item)

    # ---- Following methods are for deleting a plugin or poi from the database in the management tab --------------

    # Provides the functionality to delete a project by right clicking on it
    def rightClickOnPlugin(self, point):
        # Infos about the node selected.
        index = self.window.pluginManagement_list.indexAt(point)

        if not index.isValid():
            return

        item = self.window.projectNavigator_tree.itemAt(point)
        name = item.text(0)  # The text of the node.

        # We build the menu.
        menu = QtWidgets.QMenu()

        menu.addAction("Delete", self.showConfirmationDeletePlugin)

        menu.exec_(self.window.pluginManagement_list.mapToGlobal(point))

    # Deletes a plugin
    def callDeletePlugin(self):
        if self.window.pluginManagement_list.currentItem():
            plugin = self.window.pluginManagement_list.currentItem().text()
            deleteAPlugin(plugin)

            self.window.pluginManagement_list.clear()
            self.window.pluginSelection_dropdown.clear()

            self.populatePluginFields()

    # Deletes a poi from plugin
    # def callDeletePoiFromPlugin(self):
    #     if self.window.poiManagement_list.currentItem():
    #         pluginDict = getCurrentPluginInfo(self.window.dpoimPlugin_dropdown.currentText())
    #         name = self.window.dpoimPlugin_dropdown.currentText()
    #         modifiedPlugin = removePoiFromPlugin(pluginDict, self.window.poiManagement_list.currentItem().text())
    #         deleteAPoiFromPlugin(name, modifiedPlugin)
    #         self.window.poiManagement_list.clear()
    #         self.populatePoiFromPlugin()

    # ---- Following methods are for calling and showing the different windows in the management tab -----------------

    # Show the confirmation window when deleting a plugin
    def showConfirmationDeletePlugin(self):
        self.callDeletePlugin()

    # Open up file explorer to select a file for Plugin predefined line edit
    def showFileExplorer(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmPluginStructure_lineEdit.setText(name)

    # Open up file explorer to select a file for Poi predefined line edit
    def showFileExplorer_predefined(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpoimPredefined_lineEdit.setText(name)

    # ---- Following methods are for misc. stuff in the management tab --------------------------------------------

    def checkUncheckAllPlugins(self):
        if self.window.checkAllPlugins_checkBox.isChecked():
            for i in range(self.window.addToPlugin_list.count()):
                item = self.window.addToPlugin_list.item(i)
                item.setCheckState(QtCore.Qt.Checked)

        elif self.window.checkAllPlugins_checkBox.checkState() == 0:
            for i in range(self.window.addToPlugin_list.count()):
                item = self.window.addToPlugin_list.item(i)
                item.setCheckState(QtCore.Qt.Unchecked)


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
