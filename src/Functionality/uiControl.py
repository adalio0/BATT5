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
from src.GUI.python_files.popups.xmlEditor import XMLEditor
from src.GUI.python_files.popups.analysisResultView import Analysis_Window
from src.GUI.python_files.popups.documentationView import Documentation_Window
from src.GUI.python_files.popups.outputFieldView import OutputWindow
from src.GUI.python_files.popups.areyousure import Ui_Form
from src.Functionality.staticAnalysis import staticAnalysis
from src.Functionality.radareTerminal import Terminal
from src.Functionality.poiManagement import *
from src.Functionality.pluginManagement import *
from src.Functionality.database import *
from src.Functionality.search import *
from src.Functionality.dynamicAnalysis import dynamicAnalysis

dynamic = False
allpoiTypeCheck = False


class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()
        self.window = Ui_BATT5()
        self.window.setupUi(self)

        # ---- Main Window ---------------------------------

        # Populate the projects box with current projects
        self.populateProjectBox()

        # Populate the management plugin box with the current plugins
        self.populatePluginBox()

        # Populate the dropdown list of plugins
        self.populatePluginDD()

        # Populate the management plugin dropdown
        self.populateManagePluginDD()

        # Populate the management poi list with poi from plugin
        self.populatePoiFromPlugin()

        # Initialize the project properties
        # Terminal also initialized here
        self.setProject()

        # Unlocks dynamic if static has already been performed on the project
        self.unlockDynamic()

        # Locks static if it has already been performed
        self.lockStatic()

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
        self.window.actionSave_Analysis.setShortcut("Ctrl+alt+S")
        self.window.actionSave_Analysis.triggered.connect(self.showAnalysisWindow)

        # Clicking on Windows menu bar calls..

        # Clicking on Help menu bar calls showDocumentWindow method
        self.window.actionDocumentation.triggered.connect(self.showDocumentationWindow)

        # ---- Analysis Tab ---------------------------------

        # Clicking will clear the comment box text
        self.window.commentClear_button.clicked.connect(self.clearComment)
        self.window.commentSave_button.clicked.connect(self.callSaveComment)

        # When clicking a Project in the project box, the project properties will update to the selected project
        self.window.projectNavigator_tree.itemSelectionChanged.connect(self.setProject)

        # right click functionality
        self.window.projectNavigator_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.window.projectNavigator_tree.customContextMenuRequested.connect(self.menuContextTree)

        # ---- Search Functions ---------------------------------
        # returns the searched elements in the project list
        self.window.projectSearch_lineEdit.returnPressed.connect(self.callSearchProject)

        # returns the searched elements in the poi list
        self.window.poiSearch_lineEdit.returnPressed.connect(self.callSearchPoi)

        # returns the searched elements in the plugin list
        self.window.pluginManagementSearch_lineEdit.returnPressed.connect(self.callSearchPluginM)

        # returns the searched elements in the poi list
        self.window.poiManagementSeach_lineEdit.returnPressed.connect(self.callSearchPoiM)

        # When clicking refresh it does things
        self.window.refresh_button.clicked.connect(self.refresh)

        # check or uncheck all elements in poi list
        self.window.check_allpoi.stateChanged.connect(self.checkstate_poi)
        # ---- Comment Functionality ---------------------------------
        self.window.poi_list.currentItemChanged.connect(self.callHighlightTable)

        self.window.POI_tableWidget.currentItemChanged.connect(self.callHighlightList)

        # ---- Filters ---------------------------------
        # When changing POI type in the drop down will update whats displayed
        self.window.poiType_dropdown.currentIndexChanged.connect(self.displayPoi)

        # ---- Console -------------------------------------------
        # Executes the input command in the radare prompt
        self.window.radareConsoleIn_lineEdit.returnPressed.connect(self.inputCommand)

        # ---- Plugin Controls -----------------------------

        # Clicking on Generate Script button calls showOutputWindow method
        self.window.generateScript_button.clicked.connect(self.showOutputWindow)

        # Clicking on Run Static Analysis button calls runStatic method
        self.window.runStaticAnalysis_button.clicked.connect(self.runStatic)

        # Clicking on Run Dynamic Analysis button calls runDynamic method
        self.window.runDynamicAnalysis_button.clicked.connect(self.runDynamic)

        # ---- Management Tab -------------------------------

        # Clicking on Plugin Structure browse button calls showFileExplorer method
        self.window.dpmPluginStructure_button.clicked.connect(self.showFileExplorer)

        # Clicking on browse plugin function output source
        self.window.dpmOutFuncSource_button.clicked.connect(self.showFileExplorer_outFuncSource)

        # Creating new plugin from xml
        self.window.dpmSave_button.clicked.connect(self.callProcessPluginData)

        # Clicking on Plugin Predefined browse button calls showFileExplorer method (xmlEditor for now)
        self.window.dpoimPredefined_button.clicked.connect(self.showFileExplorer_predefined)

        # Clicking on a plugin inside the list will show a detailed view of it
        self.window.pluginManagement_list.itemClicked.connect(self.displayPlugin)

        # Clicking on the new button below the management plugin box will allow user to create new plugin
        self.window.pluginManagementNew_button.clicked.connect(self.newPluginTemplate)

        # Clicking on the delete button while a plugin is selected on the management plugin box will delete it
        self.window.dpmDelete_button.clicked.connect(self.deletePlugin)

        # Clicking on a poi inside the list will show a detailed view of it
        self.window.poiManagement_list.itemClicked.connect(self.displayPoiFromPlugin)

        # Clicking on the new button below the management poi box will allow user to create new poi
        self.window.poiManagementNew_button.clicked.connect(self.newPoiTemplate)

        # Clicking on the delete button while a poi is selected on the management poi list will delete it
        self.window.dpoimDelete_button.clicked.connect(self.callDeletePoiFromPlugin)

        # ---- View Box ------------------------------------
        self.window.switchToHistory_button.clicked.connect(self.switchToHistory)
        self.window.switchToCurrent_button.clicked.connect(self.switchToCurrent)

        # ---- Create POI Selection ----------------------
        self.window.dpoimPoiType_dropdown.currentIndexChanged.connect(self.callSwitchPOITypeView)
        self.window.dpoimSave_button.clicked.connect(self.callProcessPOIData)

        # ---- Create Plugin Selection ----------------------
        self.window.dpmCreate_dropdown.currentIndexChanged.connect(self.callSwitchPluginCreateView)

        # ---- Select listener ------------------------------
        self.window.projectSearch_lineEdit.installEventFilter(self)
        self.window.poiSearch_lineEdit.installEventFilter(self)
        self.window.pluginManagementSearch_lineEdit.installEventFilter(self)
        self.window.poiManagementSeach_lineEdit.installEventFilter(self)
        self.window.radareConsoleIn_lineEdit.installEventFilter(self)

    # ---- Following methods are all the functionality currently implemented into main window -----------------

    # Used for letting the user know where they are typing
    def eventFilter(self, obj, event):
        global focus
        # if selected (clicked on)
        if event.type() == QEvent.FocusIn:
            # if search box selected, clear "Search.."
            if obj == self.window.projectSearch_lineEdit or obj == self.window.poiSearch_lineEdit or obj == self.window.pluginManagementSearch_lineEdit or obj == self.window.poiManagementSeach_lineEdit:
                if obj.text() == "Search..":
                    obj.clear()
                    obj.setStyleSheet("color: black;")
            # if command input selected, clear "BATT5"
            elif obj == self.window.radareConsoleIn_lineEdit:
                if obj.text() == "BATT5$":
                    obj.clear()
                    obj.setStyleSheet("color: black;")

        # if not selected
        elif event.type() == QEvent.FocusOut:
            # if clicked out of project search bar, fill with "Search.." and repopulate with correct original data
            if obj == self.window.projectSearch_lineEdit:
                if obj.text() == "":
                    obj.setStyleSheet("color: rgb(136, 138, 133);")
                    obj.setText("Search..")
                    self.window.projectNavigator_tree.clear()
                    self.populateProjectBox()
            # if clicked out of search bar, fill with "Search.."
            elif obj == self.window.poiSearch_lineEdit:
                if obj.text() == "":
                    obj.setStyleSheet("color: rgb(136, 138, 133);")
                    obj.setText("Search..")
                    self.window.poi_list.clear()
                    self.displayPoi()
            elif obj == self.window.pluginManagementSearch_lineEdit:
                if obj.text() == "":
                    obj.setStyleSheet("color: rgb(136, 138, 133);")
                    obj.setText("Search..")
                    self.window.pluginManagement_list.clear()
                    self.populatePluginBox()
            elif obj == self.window.poiManagementSeach_lineEdit:
                if obj.text() == "":
                    obj.setStyleSheet("color: rgb(136, 138, 133);")
                    obj.setText("Search..")
                    self.window.poiManagement_list.clear()
                    # method to call all pois
            # if clicked out of command input bar, fill with "BATT5$"
            elif obj == self.window.radareConsoleIn_lineEdit:
                if obj.text() == "":
                    obj.setStyleSheet("color: rgb(136, 138, 133);")
                    obj.setText("BATT5$")

        return super(ApplicationWindow, self).eventFilter(obj, event)

    # ---- Following methods initialize the main window with all the project, plugin and poi data -----------

    def menuContextTree(self, point):
        # Infos about the node selected.
        index = self.window.projectNavigator_tree.indexAt(point)

        if not index.isValid():
            return

        item = self.window.projectNavigator_tree.itemAt(point)
        name = item.text(0)  # The text of the node.

        # We build the menu.
        menu = QtWidgets.QMenu()
        menu.addAction("Delete", self.deleteProject)
        # menu.addAction("Delete", self.showConfirmationDeleteProject)

        menu.exec_(self.window.projectNavigator_tree.mapToGlobal(point))

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
            self.displayPoi()
        else:
            self.window.POI_tableWidget.clear()
            self.window.poi_list.clear()
        self.unlockDynamic()

        # Set up command prompt
        self.terminal = Terminal(binaryPath, self.window.radareConsoleIn_lineEdit, self.window.radareConsoleOut_text)

    # Initialize the plugin box with all the current plugins from database
    def populatePluginBox(self):
        plugins = getPlugins()
        self.window.pluginManagement_list.addItems(plugins)

    # Initialize the plugin dropdown list with all the current plugins from database
    def populatePluginDD(self):
        plugins = getPlugins()
        self.window.pluginSelection_dropdown.addItems(plugins)

    # Initialize the management plugin dropdown list with all the current plugins from database
    def populateManagePluginDD(self):
        plugins = getPlugins()
        self.window.dpoimPlugin_dropdown.addItems(plugins)

    # Initialize the poi list with all the current poi from plugin from database
    def populatePoiFromPlugin(self):
        if self.window.dpoimPlugin_dropdown.currentText():
            pois = getPoisFromPlugin(self.window.dpoimPlugin_dropdown.currentText())
            self.window.poiManagement_list.addItems(pois)

    # ---- Following methods provide vital (word) for performing static analysis ---------------------------

    # runs Static Analysis w/ database stuff
    def runStatic(self):
        if self.window.runStaticAnalysis_button.text() == 'Run Static Analysis':
            # print('PERFORMING SA')
            self.window.runDynamicAnalysis_button.setStyleSheet("background-color:;")
            self.window.runDynamicAnalysis_button.setStyleSheet("color:;")

            if not checkStatic():
                # Get the path of the binary file and run static analysis
                path = getCurrentFilePath()
                poi = staticAnalysis(path)

                # Save the results of static into the database
                saveStatic(poi)
                self.displayPoi()

        elif self.window.runStaticAnalysis_button.text() == 'Return to Static Analysis':
            # print('RETURNING TO SA')
            self.window.analysisType_stack.setCurrentIndex(0)
            self.window.runStaticAnalysis_button.setText('Run Static Analysis')
            self.lockStatic()

    # Displays POIs in the Analysis box
    def displayPoi(self):
        self.window.POI_tableWidget.clear()
        self.window.poi_list.clear()
        poi = str(self.window.poiType_dropdown.currentText())
        if poi == 'Extract All':
            self.enableCheck()
            functions, strings, variables, dlls, structs = getAllPoi(poi)
            self.window.POI_tableWidget.setColumnCount(5)
            self.window.POI_tableWidget.setHorizontalHeaderLabels(["Functions", "Strings", "Variables", "DLL's", "Structs"])

            if self.window.pluginSelection_dropdown.currentText() == 'None':
                # Call method to display every poi
                self.displayAll(functions, strings, variables, dlls, structs)
            else:
                filterContent = getFilterPoi(self.window.pluginSelection_dropdown.currentText())
                self.displayAllFiltered(filterContent, functions, strings, variables, dlls, structs)
        else:
            content = getPoi(poi)
            # Call appropriate method to display poi
            if poi == 'Function':
                self.enableCheck()
                if self.window.pluginSelection_dropdown.currentText() == 'None':
                    self.displayFunctions(content)
                else:
                    filterContent = getFilterPoi(self.window.pluginSelection_dropdown.currentText())
                    self.displayFilteredFunctions(filterContent, content)
            elif poi == 'String':
                self.disableCheck()
                if self.window.pluginSelection_dropdown.currentText() == 'None':
                    self.displayString(content)
                else:
                    filterContent = getFilterPoi(self.window.pluginSelection_dropdown.currentText())
                    self.displayFilterStrings(filterContent, content)
            elif poi == 'Variable':
                self.disableCheck()
                if self.window.pluginSelection_dropdown.currentText() == 'None':
                    self.displayVariable(content)
                else:
                    filterContent = getFilterPoi(self.window.pluginSelection_dropdown.currentText())
                    self.displayFilteredVariable(filterContent, content)
            elif poi == 'DLL':
                self.disableCheck()
                if self.window.pluginSelection_dropdown.currentText() == 'None':
                    self.displayDll(content)
                else:
                    filterContent = getFilterPoi(self.window.pluginSelection_dropdown.currentText())
                    self.displayFilteredDll(filterContent, content)
            elif poi == 'Struct':
                self.disableCheck()
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

    # Displays all extracted pois from Static Analysis in Analysis box and POI box
    def displayAll(self, functions, strings, variables, dlls, structs):
        global allpoiTypeCheck
        allpoiTypeCheck = True
        # Get the longest number of keys between functions, strings, variables, dlls
        length = len(functions)
        if len(strings) > length:
            length = len(strings)
        elif len(variables) > length:
            length = len(variables)
        elif len(dlls) > length:
            length = len(dlls)
        elif len(structs) > length:
            length = len(structs)

        self.window.POI_tableWidget.setRowCount(length)

        self.window.poi_list.addItem(QListWidgetItem("-----FUNCTIONS-----"))
        for i in range(len(functions)):
            if 'name' in functions[i]:
                tableItem = QTableWidgetItem(functions[i]['name'])
                if getComment(functions[i]['name'], "Function", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 0, tableItem)
            item = QListWidgetItem(functions[i]['name'])
            # set icon
            if getComment(functions[i]['name'], "Function", self.window.comment_text):
                addIcon(item)
            item.setCheckState(QtCore.Qt.Checked)
            self.window.poi_list.addItem(item)

        self.window.poi_list.addItem(QListWidgetItem("-----STRINGS-----"))
        for i in range(len(strings)):
            if 'string' in strings[i]:
                tableItem = QTableWidgetItem(strings[i]['string'])
                if getComment(strings[i]['string'], "String", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 1, tableItem)
            item = QListWidgetItem(strings[i]['string'])
            # set icon
            if getComment(strings[i]['string'], "String", self.window.comment_text):
                addIcon(item)
            self.window.poi_list.addItem(item)

        self.window.poi_list.addItem(QListWidgetItem("-----VARIABLES-----"))
        for i in range(len(variables)):
            if 'name' in variables[i]:
                tableItem = QTableWidgetItem(variables[i]['name'])
                if getComment(variables[i]['name'], "Variable", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 2, tableItem)
            item = QListWidgetItem(variables[i]['name'])
            # set icon
            if getComment(variables[i]['name'], "Variable", self.window.comment_text):
                addIcon(item)
            self.window.poi_list.addItem(item)

        self.window.poi_list.addItem(QListWidgetItem("-----DLL'S-----"))
        for i in range(len(dlls)):
            if 'name' in dlls[i]:
                tableItem = QTableWidgetItem(dlls[i]['name'])
                if getComment(dlls[i]['name'], "DLL", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 3, tableItem)
            item = QListWidgetItem(dlls[i]['name'])
            if getComment(dlls[i]['name'], "DLL", self.window.comment_text):
                addIcon(item)
            self.window.poi_list.addItem(item)

        self.window.poi_list.addItem(QListWidgetItem("-----STRUCTS-----"))
        for i in range(len(structs)):
            if 'type' in structs[i]:
                tableItem = QTableWidgetItem(structs[i]['type'])
                if getComment(structs[i]['type'], "Struct", self.window.comment_text):
                    highlightCell(tableItem)
                self.window.POI_tableWidget.setItem(i, 4, tableItem)
            item = QListWidgetItem(structs[i]['type'])
            if getComment(structs[i]['type'], "Struct", self.window.comment_text):
                addIcon(item)
            self.window.poi_list.addItem(item)

    # Displays all extracted pois from Static Analysis in Analysis box and POI box
    def displayAllFiltered(self, filterContent, functions, strings, variables, dlls, structs):
        global allpoiTypeCheck
        allpoiTypeCheck = True
        # Get the longest number of keys between functions, strings, variables, dlls in filterContent
        length = len(filterContent['function'])
        if len(strings) > length:
            length = len(filterContent['string'])
        elif len(variables) > length:
            length = len(filterContent['variable'])
        elif len(dlls) > length:
            length = len(filterContent['dll'])
        # elif len(structs) > length:
        #     length = len(structs)

        self.window.POI_tableWidget.setRowCount(length)

        self.window.poi_list.addItem(QListWidgetItem("-----FUNCTIONS-----"))
        for j in range(len(filterContent['function'])):
            for i in range(len(functions)):
                if functions[i]['name'] in filterContent['function'][j]['name']:
                    tableItem = QTableWidgetItem(functions[i]['name'])
                    if getComment(functions[i]['name'], "Function", self.window.comment_text):
                        highlightCell(tableItem)
                    self.window.POI_tableWidget.setItem(j, 0, tableItem)
                    item = QListWidgetItem(functions[i]['name'])
                    # set icon
                    if getComment(functions[i]['name'], "Function", self.window.comment_text):
                        addIcon(item)
                    item.setCheckState(QtCore.Qt.Checked)
                    self.window.poi_list.addItem(item)

        self.window.poi_list.addItem(QListWidgetItem("-----STRINGS-----"))
        for j in range(len(filterContent['string'])):
            for i in range(len(strings)):
                if strings[i]['string'] in filterContent['string'][j]['name']:
                    tableItem = QTableWidgetItem(strings[i]['string'])
                    if getComment(strings[i]['string'], "String", self.window.comment_text):
                        highlightCell(tableItem)
                    self.window.POI_tableWidget.setItem(j, 1, tableItem)
                    item = QListWidgetItem(strings[i]['string'])
                    # set icon
                    if getComment(strings[i]['string'], "String", self.window.comment_text):
                        addIcon(item)
                    self.window.poi_list.addItem(item)

        self.window.poi_list.addItem(QListWidgetItem("-----VARIABLES-----"))
        for j in range(len(filterContent['variable'])):
            for i in range(len(variables)):
                if variables[i]['name'] in filterContent['variable'][j]['name']:
                    tableItem = QTableWidgetItem(variables[i]['name'])
                    if getComment(variables[i]['name'], "Variable", self.window.comment_text):
                        highlightCell(tableItem)
                    self.window.POI_tableWidget.setItem(j, 2, tableItem)
                    item = QListWidgetItem(variables[i]['name'])
                    # set icon
                    if getComment(variables[i]['name'], "Variable", self.window.comment_text):
                        addIcon(item)
                    self.window.poi_list.addItem(item)

        self.window.poi_list.addItem(QListWidgetItem("-----DLL'S-----"))
        for j in range(len(filterContent['dll'])):
            for i in range(len(dlls)):
                if dlls[i]['name'] in filterContent['dll'][j]['name']:
                    tableItem = QTableWidgetItem(dlls[i]['name'])
                    if getComment(dlls[i]['name'], "DLL", self.window.comment_text):
                        highlightCell(tableItem)
                    self.window.POI_tableWidget.setItem(j, 3, tableItem)
                    item = QListWidgetItem(dlls[i]['name'])
                    if getComment(dlls[i]['name'], "DLL", self.window.comment_text):
                        addIcon(item)
                    self.window.poi_list.addItem(item)

        # self.window.poi_list.addItem(QListWidgetItem("-----STRUCTS-----"))
        # for i in range(len(structs)):
        #     if 'type' in structs[i]:
        #         self.window.POI_tableWidget.setItem(i, 4, QTableWidgetItem(structs[i]['type']))
        #     item = QListWidgetItem(structs[i]['type'])
        #     if getComment(structs[i]['type'], "Struct", self.window.comment_text):
        #         addIcon(item)
        #     self.window.poi_list.addItem(item)

    # ---- Following methods provide all the search functionality ----------------------------------------

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

    def callHighlightTable(self):
        try:
            highlightTable(self.window.poi_list.currentItem().text(), self.window.POI_tableWidget)
            getComment(self.window.poi_list.currentItem().text(), self.window.poiType_dropdown.currentText(),
                       self.window.comment_text)
        except AttributeError:
            pass

    # ---- Following methods provide vital (word) during dynamic analysis --------------------------------

    # Takes input from user and passes it to the terminal
    def inputCommand(self):
        cmd_in = str(self.window.radareConsoleIn_lineEdit.text())
        self.terminal.processInput(cmd_in)
        self.window.radareConsoleIn_lineEdit.clear()

    # runs Dynamic Analysis
    def runDynamic(self):
        global dynamic
        if checkStatic():
            # switch views
            self.window.analysisType_stack.setCurrentIndex(1)
            self.window.runStaticAnalysis_button.setText('Return to Static Analysis')
            self.unlockStatic()

            if dynamic is False:
                dynamic = True
                # self.window.runDynamicAnalysis_button.setText("Stop Dynamic Analysis")
            else:
                dynamic = False
                self.window.runDynamicAnalysis_button.setText("Run Dynamic Analysis")
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

    # ---- Following methods are for deleting a project or plugin from the database -------------------

    # Deletes a project
    def deleteProject(self):
        if self.window.projectNavigator_tree.currentItem():
            project = self.window.projectNavigator_tree.currentItem().text(0)
            deleteAProject(project)

            self.window.projectNavigator_tree.clear()
            self.populateProjectBox()

    # Deletes a plugin
    def deletePlugin(self):
        if self.window.pluginManagement_list.currentItem():
            plugin = self.window.pluginManagement_list.currentItem().text()
            deleteAPlugin(plugin)

            self.window.pluginManagement_list.clear()
            self.window.pluginSelection_dropdown.clear()
            self.window.dpoimPlugin_dropdown.clear()

            self.populatePluginBox()
            self.populatePluginDD()
            self.populateManagePluginDD()

    # Deletes a poi from plugin
    def callDeletePoiFromPlugin(self):
        if self.window.poiManagement_list.currentItem():
            pluginDict = getCurrentPluginInfo(self.window.dpoimPlugin_dropdown.currentText())
            name = self.window.dpoimPlugin_dropdown.currentText()
            modifiedPlugin = removePoiFromPlugin(pluginDict, self.window.poiManagement_list.currentItem().text())
            deleteAPoiFromPlugin(name, modifiedPlugin)
            self.window.poiManagement_list.clear()
            self.populatePoiFromPlugin()

    # ---- Following methods are for calling and showing the different windows ---------------------------

    # Shows NewProject window
    def showNewProject(self):
        self.ui = ProjectWindow()
        if self.ui.exec_() == ProjectWindow.Accepted:
            self.window.projectNavigator_tree.clear()
            self.populateProjectBox()

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

    # Shows confirmation to delete project
    def showConfirmationDeleteProject(self):
        self.windowAUS = QtWidgets.QDialog()
        self.ui = Ui_Form()
        self.ui.setupUi(self.windowAUS)
        self.ui.windowAUS.show()

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

    # Opens up an xml (file) editor
    def xmlEditor(self):
        self.window = XMLEditor()
        self.window.show()

    # Open up file explorer to select a file
    def showFileExplorer(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmPluginStructure_lineEdit.setText(name)

    def showFileExplorer_outFuncSource(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmOutFuncSource_lineEdit.setText(name)

    # Open up file explorer to select a file for Project Predefined line edit
    def showFileExplorer_predefined(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpoimPredefined_lineEdit.setText(name)

    # Open up file explorer, does not pass any data
    def showFileExplorerSimple(self):
        _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')

    # ---- Following methods are for misc. stuff -------------------------------------------------

    # Will save the current modifications of the project TODO: Saves the current project into our project list
    def Save(self):
        cur_path = os.getcwd()
        name = os.path.join(cur_path, '..', 'Configurations', 'random.txt')  # TODO:
        try:
            file = open(name, 'w')
            text = self.window.projectProperties_text.toPlainText()
            file.write(text)
            file.close()
        except FileNotFoundError or AttributeError:
            pass

    # Will allow the user to change the name of the file, saving the current modifications of it TODO: ???????
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
    def clearComment(self):
        self.window.comment_text.clear()

    # disable checkbox
    def disableCheck(self):
        self.window.check_allpoi.setCheckable(False)

    # enable checkbox

    def enableCheck(self):
        self.window.check_allpoi.setCheckable(True)

    # Checks if static has been performed, if it has unlock dynamic
    def unlockDynamic(self):
        if checkStatic():
            self.window.runDynamicAnalysis_button.setStyleSheet("background-color:;")
            self.window.runDynamicAnalysis_button.setStyleSheet("color:;")
        else:
            self.window.runDynamicAnalysis_button.setStyleSheet("background-color: rgb(186, 189, 182);")
            self.window.runDynamicAnalysis_button.setStyleSheet("color: rgb(136, 138, 133);")

    def unlockStatic(self):
        self.window.runStaticAnalysis_button.setStyleSheet("background-color:;")
        self.window.runStaticAnalysis_button.setStyleSheet("color:;")

    def lockStatic(self):
        if checkStatic():
            self.window.runStaticAnalysis_button.setStyleSheet("background-color: rgb(186, 189, 182);")
            self.window.runStaticAnalysis_button.setStyleSheet("color: rgb(136, 138, 133);")

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

    def callSwitchPOITypeView(self):
        switchPOITypeView(self.window.dpoimPoiType_dropdown.currentText(), self.window.addPOI_stack)

    def callSwitchPluginCreateView(self):
        switchPluginCreateView(self.window.dpmCreate_dropdown.currentText(), self.window.createPlugin_stack)

    def callProcessPluginData(self):
        processPluginData(self.window.dpmCreate_dropdown.currentText(), self.window.dpmPluginStructure_lineEdit,
                          self.window.dpmPluginName_lineEdit, self.window.dpmPluginDesc_lineEdit,
                          self.window.dpmOutName_lineEdit, self.window.dpmOutFuncName_lineEdit,
                          self.window.dpmOutFuncSource_lineEdit)

        self.window.pluginManagement_list.clear()
        self.window.pluginSelection_dropdown.clear()
        self.window.dpoimPlugin_dropdown.clear()

        self.populatePluginBox()
        self.populatePluginDD()
        self.populateManagePluginDD()
        self.populatePoiFromPlugin()

    # save data from poi view in management tab
    def callProcessPOIData(self):
        if self.window.dpoimPoiType_dropdown.currentText() == "Function":
            processPOIDataFun(self.window.dpoimPlugin_dropdown,self.window.funcName_lineEdit, self.window.funcRetType_lineEdit, self.window.funcRetCal_lineEdit,
                self.window.funcCallFrom_lineEdit,self.window.funcDestAddress_lineEdit, self.window.funcNumParam_lineEdit)

            self.window.poiManagement_list.clear()
            self.populatePoiFromPlugin()

        if self.window.dpoimPoiType_dropdown.currentText() == "String":
            processPOIDataStr(self.window.dpoimPlugin_dropdown,self.window.strName_lineEdit,self.window.strType_lineEdit,self.window.strSize_lineEdit, 
                self.window.strCallFrom_lineEdit,self.window.strDest_lineEdit,self.window.strSection_linEdit)

            self.window.poiManagement_list.clear()
            self.populatePoiFromPlugin()

        if self.window.dpoimPoiType_dropdown.currentText() == "Variable":
            processPOIDataVar(self.window.dpoimPlugin_dropdown,self.window.varName_lineEdit,self.window.varType_lineEdit,self.window.varValue_lineEdit,self.window.varSize_lineEdit)

            self.window.poiManagement_list.clear()
            self.populatePoiFromPlugin()

        if self.window.dpoimPoiType_dropdown.currentText() == "DLL":
            processPOIDataDLL(self.window.dpoimPlugin_dropdown,self.window.dllName_lineEdit)

            self.window.poiManagement_list.clear()
            self.populatePoiFromPlugin()

        if self.window.dpoimPoiType_dropdown.currentText() == "Packet Protocol":
            processPOIDataPP(self.window.dpoimPlugin_dropdown,self.window.protoName_lineEdit,
                self.window.protoFieldName_lineEdit,self.window.protoFieldType_lineEdit)

            self.window.poiManagement_list.clear()
            self.populatePoiFromPlugin()

        # if self.window.dpoimPoiType_dropdown.currentText() == "Struct":
        #     processPOIDataS(self.window.dpoimPlugin_dropdown,self.window.StructTBD_text)

    def callSaveComment(self):
        saveComment(self.window.comment_text.toPlainText(), self.window.poi_list.currentItem().text(),
                    self.window.poiType_dropdown.currentText())
        addIcon(self.window.poi_list.currentItem())
        highlightCell(self.window.POI_tableWidget.currentItem())

    def callHighlightList(self):
        try:
            HighlightList(self.window.POI_tableWidget.currentItem().text(), self.window.poi_list)
        except AttributeError:
            pass

    # Displays a detailed view of the plugin
    def displayPlugin(self):
        item = self.window.pluginManagement_list.currentItem().text()
        name, description, poi, output = getCurrentPlugin(item)

        self.window.dpmCreate_dropdown.setCurrentIndex(1)
        self.window.dpmPluginName_lineEdit.setText(name)
        self.window.dpmPluginDesc_lineEdit.setText(description)
        self.window.dpmOutName_lineEdit.setText(output['name'])
        self.window.dpmOutFuncName_lineEdit.setText(output['functionName'])
        self.window.dpmOutFuncSource_lineEdit.setText(output['functionSource'])

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

    # Clears the labels that are used for creating a new plugin to create a new plugin
    def newPluginTemplate(self):
        self.window.dpmCreate_dropdown.setCurrentIndex(1)
        self.window.dpmPluginName_lineEdit.clear()
        self.window.dpmPluginDesc_lineEdit.clear()
        self.window.dpmOutName_lineEdit.clear()
        self.window.dpmOutFuncName_lineEdit.clear()
        self.window.dpmOutFuncSource_lineEdit.clear()

    def newPoiTemplate(self):
        poiType = self.window.dpoimPoiType_dropdown.currentText()

        if poiType == 'Pull From Predefined Dataset':
            self.window.dpoimPredefined_lineEdit.clear()

        elif poiType == 'Function':
            self.window.funcName_lineEdit.clear()

        elif poiType == 'String':
            self.window.strName_lineEdit.clear()

        elif poiType == 'Variable':
            self.window.varName_lineEdit.clear()

        elif poiType == 'DLL':
            self.window.dllName_lineEdit.clear()

        elif poiType == 'Packet Protocol':
            self.window.protoName_lineEdit.clear()

        elif poiType == 'Struct':
            pass

    def refresh(self):
        self.displayPoi()

def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
