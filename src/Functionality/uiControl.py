#! /usr/bin/env python3.

import os
import sys
import glob
import xml.etree.ElementTree as ET
import pymongo
from pathlib import Path

sys.path.insert(0, Path(__file__).parents[2].as_posix())

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import QEvent
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from src.GUI.python_files.BATT5_GUI import Ui_BATT5
from src.GUI.python_files.popups.errors import ErrFile, Errx86, ErrRadare
from src.Functionality.newProject import ProjectWindow
from src.GUI.python_files.popups.xmlEditor import XMLEditor
from src.GUI.python_files.popups.analysisResultView import Analysis_Window
from src.GUI.python_files.popups.documentationView import Documentation_Window
from src.GUI.python_files.popups.outputFieldView import OutputWindow
from src.Functionality.staticAnalysis import staticAnalysis
from src.Functionality.radareTerminal import Terminal

static = False
dynamic = False

projectList = []

class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()
        self.window = Ui_BATT5()
        self.window.setupUi(self)

        # ---- Main Window ---------------------------------

        # Populate the projects box with current projects
        self.populateProjectBox()

        # Initialize the project properties
        # Terminal also initialized here
        self.setProject()

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
        self.window.commentClear_button.clicked.connect(self.Clear)

        # When clicking a Project in the project box, the project properties will update to the selected project
        self.window.projectNavigator_tree.itemSelectionChanged.connect(self.setProject)

        # Highlights the searched elements in the project list
        self.window.projectSearch_lineEdit.returnPressed.connect(self.searchProject)

        # Highlights the searched elements in the poi list
        self.window.poiSearch_lineEdit.returnPressed.connect(self.searchPoi)
        
        # Executes the input command in the radare prompt
        self.window.radareConsoleIn_lineEdit.returnPressed.connect(self.inputCommand)

        # When changing POI type in the drop down will update whats displayed
        self.window.poiType_dropdown.currentIndexChanged.connect(self.displayPoi)

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
        self.window.dpoimPredefined_button.clicked.connect(self.showFileExplorer_predefined)

        # ---- View Box ------------------------------------
        self.window.switchToHistory_button.clicked.connect(self.switchToHistory)
        self.window.switchToCurrent_button.clicked.connect(self.switchToCurrent)

        # ---- Create Plugin Selection ----------------------
        self.window.dpoimPoiType_dropdown.currentIndexChanged.connect(self.switchPOITypeView)

        # ---- Select listener ------------------------------
        self.window.projectSearch_lineEdit.installEventFilter(self)
        self.window.poiSearch_lineEdit.installEventFilter(self)
        self.window.pluginManagementSearch_lineEdit.installEventFilter(self)
        self.window.poiManagementSeach_lineEdit.installEventFilter(self)
        self.window.radareConsoleIn_lineEdit.installEventFilter(self)

        # ----- Radare Integration --------------------------

        # Perform static analysis on a binary file
        self.window.runStaticAnalysis_button.clicked.connect(self.runStatic)

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
                    self.displayAll()
            elif obj == self.window.pluginManagementSearch_lineEdit or obj == self.window.poiManagementSeach_lineEdit:
                if obj.text() == "":
                    obj.setStyleSheet("color: rgb(136, 138, 133);")
                    obj.setText("Search..")
            # if clicked out of command input bar, fill with "BATT5$"
            elif obj == self.window.radareConsoleIn_lineEdit:
                if obj.text() == "":
                    obj.setStyleSheet("color: rgb(136, 138, 133);")
                    obj.setText("BATT5$")

        return super(ApplicationWindow, self).eventFilter(obj, event)

    # Initialize the project box with all the current projects from database
    def populateProjectBox(self):
        client = pymongo.MongoClient("mongodb://localhost:27017")
        db = client['project_data']
        posts = db['project']

        # db.project.drop()

        projects = []
        for x in posts.find():
            projects.append(QTreeWidgetItem([x.get('properties', {})['name']]))
            child = QTreeWidgetItem(projects[len(projects) - 1])
            child.setText(0, x.get('properties', {})['file'])

        tree = self.window.projectNavigator_tree
        tree.addTopLevelItems(projects)

    # Changes the project description according to the current project from database
    def setProject(self):
        selected = self.window.projectNavigator_tree.selectedItems()

        client = pymongo.MongoClient("mongodb://localhost:27017")
        db = client['project_data']
        posts = db['project']

        newdb = client['current_project']
        current = newdb['current']

        data = ""
        text = ""
        binaryPath = ""
        if selected:
            item = selected[0].text(0)
            for x in posts.find():
                prop = x.get('properties', {})
                if prop['name'] == item:
                    stats = x.get('static_analysis', {}).get('uncovered_poi', {})

                    data = {
                        'properties': {
                            'name': prop['name'],
                            'file': prop['file'],
                            'description': prop['description'],
                            'os': prop['os'],
                            'binary': prop['binary'],
                            'machine': prop['machine'],
                            'class': prop['class'],
                            'bits': prop['bits'],
                            'language': prop['language'],
                            'canary': prop['canary'],
                            'crypto': prop['crypto'],
                            'nx': prop['nx'],
                            'relocs': prop['relocs'],
                            'stripped': prop['stripped'],
                            'relro': prop['relro']
                        },  # End of Properties

                        'static_analysis': {
                            'uncovered_poi': {
                                'function': {
                                    'associated_plugin': stats.get('function')['associated_plugin'],
                                    'data': stats.get('function')['data']
                                },
                                'string': {
                                    'associated_plugin': stats.get('string')['associated_plugin'],
                                    'data': stats.get('string')['data']
                                },
                                'variable': {
                                    'associated_plugin': stats.get('variable')['associated_plugin'],
                                    'data': stats.get('variable')['data']
                                },
                                'dll': {
                                    'associated_plugin': stats.get('dll')['associated_plugin'],
                                    'data': stats.get('dll')['data']
                                },
                            }
                        },  # End of Static Analysis

                        'dynamic_analysis': {

                        }  # End of Dynamic Analysis
                    }
            newdb.current.drop()
            try:
                result = current.insert_one(data)
            except TypeError:
                pass

        for p in current.find():
            text = "<font size=3> <b>Project Description</b>: " + p.get('properties', {}).get('description') + "<br><br>"
            text += "<b>Project Properties</b>: <br>"
            text += "<b>" + "Os" + "</b>: " + p.get('properties', {}).get('os') + "<br>"
            text += "<b>" + "Binary" + "</b>: " + p.get('properties', {}).get('binary') + "<br>"
            text += "<b>" + "Machine" + "</b>: " + p.get('properties', {}).get('machine') + "<br>"
            text += "<b>" + "Class" + "</b>: " + p.get('properties', {}).get('class') + "<br>"
            text += "<b>" + "Bits" + "</b>: " + p.get('properties', {}).get('bits') + "<br>"
            text += "<b>" + "Language" + "</b>: " + p.get('properties', {}).get('language') + "<br>"
            text += "<b>" + "Canary" + "</b>: " + p.get('properties', {}).get('canary') + "<br>"
            text += "<b>" + "Crypto" + "</b>: " + p.get('properties', {}).get('crypto') + "<br>"
            text += "<b>" + "Nx" + "</b>: " + p.get('properties', {}).get('nx') + "<br>"
            text += "<b>" + "Relocs" + "</b>: " + p.get('properties', {}).get('relocs') + "<br>"
            text += "<b>" + "Stripped" + "</b>: " + p.get('properties', {}).get('stripped') + "<br>"
            text += "<b>" + "Relro" + "</b>: " + p.get('properties', {}).get('relro') + "<br> </font>"

        self.window.projectProperties_text.setHtml(text)

        for p in current.find():
            binaryPath = p.get('properties', {}).get('file')

        # Set up command prompt
        self.terminal = Terminal(binaryPath, self.window.radareConsoleIn_lineEdit, self.window.radareConsoleOut_text)

    # Initialize the project box with all the current projects
    def populateProjectBox_xml(self):
        cur_path = os.getcwd()
        new_path = os.path.join(cur_path, '..', 'Configurations')

        projects = []
        for file in glob.glob(new_path + "/**/" + '*.xml', recursive=True):
            tree = ET.parse(file)
            root = tree.getroot()

            for p in root.iter('Project'):
                if p.get('name') is not "":
                    projects.append(QTreeWidgetItem([p.get('name')]))
                    child = QTreeWidgetItem(projects[len(projects) - 1])
                    child.setText(0, p.get('file'))

        tree = self.window.projectNavigator_tree
        tree.addTopLevelItems(projects)

    # Changes the project description according to the current project
    def setProject_xml(self):
        selected = self.window.projectNavigator_tree.selectedItems()
        cur_path = os.getcwd()

        file = ''
        if selected:
            item = selected[0].text(0)
            item = item.replace(" ", "")
            try:
                file = os.path.join(cur_path, '..', 'Configurations', item + '.xml')

                currentXml = os.path.join(cur_path, '..', 'Configurations', 'current.xml')
                tree = ET.parse(currentXml)
                root = tree.getroot()

                for current in root.iter('Current'):
                    current.set('name', (item + '.xml'))
                tree.write(currentXml)
            except IndexError or FileNotFoundError:
                pass
        else:
            file = os.path.join(cur_path, '..', 'Configurations', 'current.xml')

        try:
            tree = ET.parse(file)
            root = tree.getroot()

            if file.endswith('current.xml'):
                for current in root.iter('Current'):
                    tree = ET.parse(os.path.join(cur_path, '..', 'Configurations', current.get('name')))
                    root = tree.getroot()

            text = ""
            binaryPath = ""
            for p in root.iter('Project'):
                text = "<font size=2> <b>Project Description</b>: " + p.get('description') + "<br><br>"
                text += "<b>Project Properties</b>: <br> </font> "
                binaryPath = p.get('file')

            for child in root.iter():
                if child.tag != "Project" and child.get('name') is not None:
                    text += "<font size=2> <b>" + child.tag + "</b>" + ": " + child.get('name') + "<br> </font>"

            self.window.projectProperties_text.setHtml(text)

            # Set up command prompt
            self.terminal = Terminal(binaryPath, self.window.radareConsoleIn_lineEdit, self.window.radareConsoleOut_text)

        except FileNotFoundError:
            pass

    # runs Static Analysis w/ database stuff
    # TODO: The static analysis data is too big that it overwrites the other poi types.
    def runStatic(self):
        global static
        static = True
        self.window.runDynamicAnalysis_button.setStyleSheet("background-color:;")
        self.window.runDynamicAnalysis_button.setStyleSheet("color:;")

        client = pymongo.MongoClient("mongodb://localhost:27017")
        db = client['current_project']
        current = db['current']

        path = ''
        analysis = ''
        for p in current.find():
            path = p.get('properties', {}).get('file')
            analysis = p.get('static_analysis', {}).get('uncovered_poi', {}).get('function', {})

        try:
            # function, string, variable, dll = staticAnalysis(path)
            poi = staticAnalysis(path)

            for i in range(len(poi[0])):
                db.current.findOneAndUpdate({

                }, {
                    '$set': {
                        'function': {
                            'associated_plugin': str(self.window.poiType_dropdown.currentText()),
                            ('data' + str(i)): poi[0][i]
                        }
                    },
                }, upsert=False)
                # analysis[('data' + str(i))] = poi[0][i]

            # print(analysis)

            try:
                db.current.update_one({

                }, {
                    '$set': {
                        'static_analysis': {
                            'uncovered_poi': {
                                'function': {
                                    'associated_plugin': str(self.window.poiType_dropdown.currentText()),
                                    'data': poi[0][1]
                                },
                                'string': {
                                    'associated_plugin': str(self.window.poiType_dropdown.currentText()),
                                    'data': poi[1][0]
                                },
                                'variable': {
                                    'associated_plugin': str(self.window.poiType_dropdown.currentText()),
                                    'data': 'stuff'
                                },
                                'dll': {
                                    'associated_plugin': str(self.window.poiType_dropdown.currentText()),
                                    'data': 'stuff'
                                }
                            }
                        }
                    }
                }, upsert=False)
            except IndexError:
                pass
        except:
            print("An error occurred inside Radare2")

        self.displayPoi()

    # runs Static Analysis
    def runStatic_xml(self):
        global static
        static = True
        self.window.runDynamicAnalysis_button.setStyleSheet("background-color:;")
        self.window.runDynamicAnalysis_button.setStyleSheet("color:;")

        tree = ET.parse(os.path.join(os.getcwd(), '..', 'Configurations', 'current.xml'))
        root = tree.getroot()

        currentProject = ""
        for current in root.iter('Current'):
            currentProject = current.get('name')

        tree = ET.parse(os.path.join(os.getcwd(), '..', 'Configurations', currentProject))
        root = tree.getroot()

        path = ''
        for p in root.iter('Project'):
            path = p.get('file')

        try:
            staticAnalysis(path)
        except:
            print("Radare2 not installed cannot start static analysis.")

        self.displayPoi()

    # Dispalys POIs in the Analysis box
    # TODO: make sure the stuff gets properly displayed in the gui
    def displayPoi(self):
        self.window.POI_tableWidget.clear()
        self.window.poi_list.clear()
        poi = str(self.window.poiType_dropdown.currentText())
        if poi == 'Extract All':
            self.displayAll()
        else:
            client = pymongo.MongoClient("mongodb://localhost:27017")
            db = client['current_project']
            current = db['current']

            data = ''
            for x in current.find():
                data = x.get('static_analysis', {}).get('uncovered_poi', {})

            for key in data:
                if key == poi.lower():
                    self.window.POI_tableWidget.setHorizontalHeaderLabels([poi])
                    self.window.POI_tableWidget.setColumnCount(1)
                    content = data.get(key, {})['data']
                    entries = []
                    i = 0
                    try:
                        for collection in content:
                            entries.append(collection)
                            self.window.POI_tableWidget.setRowCount(len(entries))
                            self.window.POI_tableWidget.setItem(i, 0, QTableWidgetItem(str(content['name'])))
                            self.window.POI_tableWidget.resizeColumnToContents(0)
                            i += 1
                    except TypeError:
                        pass
            if poi == 'Function':
                self.displayFunctions()
            elif poi == 'String':
                self.displayString()
            elif poi == 'Variable':
                self.displayVariable()
            elif poi == 'DLL':
                self.displayDll()

    # Displays the functions extracted from Static Analysis in the POI box
    def displayFunctions(self):
        try:
            f = open("function.txt", "r")

            i = 0
            for line in f.read().split("\n\n")[:]:
                line = line.split(" ")[-1]
                item = QListWidgetItem(line)

                if i > 1:
                    item.setCheckState(QtCore.Qt.Checked)
                    self.window.poi_list.addItem(item)
                else:
                    i += 1
            f.close()
        except FileNotFoundError:
            pass

    # Displays the strings extracted from Static Analysis in the POI box
    def displayString(self):
        try:
            f = open("string.txt", "r")

            i = 0
            for line in f.read().split("\n\n")[:]:
                line = line.split(" ", 9)[-1]
                item = QListWidgetItem(line)

                if i > 1:
                    self.window.poi_list.addItem(item)
                else:
                    i += 1
            f.close()
        except FileNotFoundError:
            pass

    # Displays the variables extracted from Static Analysis in the POI box
    def displayVariable(self):
        try:
            f = open("variable.txt", "r")

            for line in f.read().split("\n\n")[:]:
                try:
                    line = line.split(" ")[1]
                    item = QListWidgetItem(line)

                    self.window.poi_list.addItem(item)
                except IndexError:
                    pass
            f.close()
        except FileNotFoundError:
            pass

    # Displays the dlls extracted from Static Analysis in the POI box
    def displayDll(self):
        try:
            f = open("dll.txt", "r")

            i = 0
            for line in f.read().split("\n\n")[:]:
                line = line.split(" ")[-1]
                item = QListWidgetItem(line)

                if i > 1:
                    item.setCheckState(QtCore.Qt.Checked)
                    self.window.poi_list.addItem(item)
                else:
                    i += 1
            f.close()
        except FileNotFoundError:
            pass

    # Displays the all extracted pois from Static Analysis in the POI box
    def displayAll(self):
        try:
            f = open("function.txt", "r")

            self.window.poi_list.addItem(QListWidgetItem("-----FUNCTIONS-----"))
            self.window.POI_tableWidget.setHorizontalHeaderLabels(["Functions", "Strings", "Variables", "DLL's"])
            self.window.POI_tableWidget.setColumnCount(4)

            entries = []
            i = 0
            j = 0
            for line in f.read().split("\n\n")[:]:
                rowPos = self.window.POI_tableWidget.rowCount()
                line = line.split(" ")[-1]
                item = QListWidgetItem(line)
                entries.append(line)
                self.window.POI_tableWidget.setRowCount(len(entries))
                if i > 1:
                    item.setCheckState(QtCore.Qt.Unchecked)
                    self.window.poi_list.addItem(item)
                    self.window.POI_tableWidget.setItem(j, 0, QTableWidgetItem(str(line)))
                    j += 1
                    self.window.POI_tableWidget.resizeColumnToContents(0)
                else:
                    i += 1

            f.close()
            f = open("string.txt", "r")

            self.window.poi_list.addItem(QListWidgetItem("-----STRINGS-----"))
            i = 0
            j = 0
            for line in f.read().split("\n\n")[:]:
                # rowPos = self.window.POI_tableWidget.rowCount()
                line = line.split(" ", 9)[-1]
                item = QListWidgetItem(line)

                if i > 1:
                    self.window.poi_list.addItem(item)
                    # self.window.POI_tableWidget.insertRow(rowPos)
                    self.window.POI_tableWidget.setItem(j, 1, QTableWidgetItem(str(line)))
                    j += 1
                    self.window.POI_tableWidget.resizeColumnToContents(1)
                else:
                    i += 1

            f.close()
            f = open("variable.txt", "r")

            self.window.poi_list.addItem(QListWidgetItem("-----VARIABLES-----"))
            j = 0
            for line in f.read().split("\n\n")[:]:
                # rowPos = self.window.POI_tableWidget.rowCount()
                try:
                    line = line.split(" ")[1]
                    item = QListWidgetItem(line)

                    self.window.poi_list.addItem(item)
                    # self.window.POI_tableWidget.insertRow(rowPos)
                    self.window.POI_tableWidget.setItem(j, 2, QTableWidgetItem(str(line)))
                    j += 1
                    self.window.POI_tableWidget.resizeColumnToContents(2)
                except IndexError:
                    pass

            f.close()
            f = open("dll.txt", "r")

            self.window.poi_list.addItem(QListWidgetItem("-----DLL'S-----"))
            i = 0
            j = 0
            for line in f.read().split("\n\n")[:]:
                rowPos = self.window.POI_tableWidget.rowCount()
                line = line.split(" ")[-1]
                item = QListWidgetItem(line)

                if i > 1:
                    item.setCheckState(QtCore.Qt.Unchecked)
                    self.window.poi_list.addItem(item)
                    # self.window.POI_tableWidget.insertRow(rowPos)
                    self.window.POI_tableWidget.setItem(j, 3, QTableWidgetItem(str(line)))
                    j += 1
                    self.window.POI_tableWidget.resizeColumnToContents(3)
                else:
                    i += 1
        except FileNotFoundError:
            pass

    # Search functionality for the project box
    def searchProject(self):
        search = str(self.window.projectSearch_lineEdit.text())
        result = self.window.projectNavigator_tree.findItems(search, QtCore.Qt.MatchContains)

        projects = []
        item = ''

        j = 0
        if search:
            for i in range(self.window.projectNavigator_tree.topLevelItemCount()):
                try:
                    item = result[j]
                except IndexError:
                    pass
                if item.text(0) in self.window.projectNavigator_tree.topLevelItem(i).text(0):
                    projects.append(QTreeWidgetItem([item.text(0)]))
                    child_text = item.child(0).text(0)
                    child = QTreeWidgetItem(projects[len(projects) - 1])
                    child.setText(0, child_text)
                    j += 1
            tree = self.window.projectNavigator_tree
            tree.clear()
            tree.addTopLevelItems(projects)
        else:
            tree = self.window.projectNavigator_tree
            tree.clear()
            self.populateProjectBox()

    # Search functionality for the poi box
    def searchPoi(self):
        search = str(self.window.poiSearch_lineEdit.text())
        result = self.window.poi_list.findItems(search, QtCore.Qt.MatchContains)

        poi = []
        item = ''

        j = 0
        if search:
            for i in range(self.window.poi_list.count()):
                try:
                    item = result[j]
                except IndexError:
                    pass
                if item.text() in self.window.poi_list.item(i).text():
                    poi.append(item.text())
                    j+=1
            list = self.window.poi_list
            list.clear()
            list.addItems(poi)
        else:
            list = self.window.poi_list
            list.clear()
            self.displayAll()

    # Takes input from user and passes it to the terminal
    def inputCommand(self):
        cmd_in = str(self.window.radareConsoleIn_lineEdit.text())
        self.terminal.processInput(cmd_in)
        self.window.radareConsoleIn_lineEdit.clear()
    
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
            self.window.runDynamicAnalysis_button.setText("Run Dynamic Analysis")

    # ---- Following methods are for calling and showing the different windows ------------------------

    # Shows NewProject window
    def showNewProject(self):
        self.ui = ProjectWindow()
        if self.ui.exec_() == ProjectWindow.Accepted:
            obj = self.ui.getProject()
            projectList.append(obj)
            tree = self.window.projectNavigator_tree
            item = QTreeWidgetItem([obj.get_name(self.ui)])
            child = QTreeWidgetItem(item)
            child.setText(0,obj.get_file(self.ui))
            tree.addTopLevelItem(item)

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

    # Opens up an xml (file) editor
    def xmlEditor(self):
        self.window = XMLEditor()
        self.window.show()

    # Open up file explorer to select a file
    def showFileExplorer(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmPluginStructure_lineEdit.setText(name)

    # Open up file explorer to select a file for Project Predefined line edit
    def showFileExplorer_predefined(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        # self.window.dpmPluginPredefined_lineEdit.setText(name)

    # Open up file explorer, does not pass any data
    def showFileExplorerSimple(self):
        _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')

    # ---- Following methods are for misc. stuff -------------------------------------------------

    # Will save the current modifications of the file TODO: testing not final
    def Save(self):
        cur_path = os.getcwd()
        name = os.path.join(cur_path, '..', 'Configurations', 'random.txt')  # TODO: Get correct file to Save
        try:
            file = open(name, 'w')
            text = self.window.projectProperties_text.toPlainText()
            file.write(text)
            file.close()
        except FileNotFoundError or AttributeError:
            pass

    # Will allow the user to change the name of the file, saving the current modifications of it TODO: testing not final
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

    # From current to history
    def switchToHistory(self):
        self.window.changeViews_stack.setCurrentIndex(1)

    def switchToCurrent(self):
        self.window.changeViews_stack.setCurrentIndex(0)

    def switchPOITypeView(self):
        poiType = self.window.dpoimPoiType_dropdown.currentText()
        if poiType == 'Pull From Predefined Dataset':
            self.window.addPOI_stack.setCurrentIndex(0)
        elif poiType == 'Function':
            self.window.addPOI_stack.setCurrentIndex(1)
        elif poiType == 'String':
            self.window.addPOI_stack.setCurrentIndex(2)
        elif poiType == 'Variable':
            self.window.addPOI_stack.setCurrentIndex(3)
        elif poiType == 'DLL':
            self.window.addPOI_stack.setCurrentIndex(4)
        elif poiType == 'Packet Protocol':
            self.window.addPOI_stack.setCurrentIndex(5)
        elif poiType == 'Struct':
            self.window.addPOI_stack.setCurrentIndex(6)

def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
