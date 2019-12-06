# ! /usr/bin/env python3.

from PyQt5 import QtWidgets
from PyQt5.QtCore import QTimer
from src.GUI.python_files.BATT5_GUI import Ui_BATT5
from src.Functionality.newProjectControl import ProjectWindow
from src.Functionality.documentationControl import DocumentationWindow
from src.Functionality.Analysis.staticAnalysis import staticAnalysis, historicAnalysis
from src.Functionality.Analysis.radareTerminal import Terminal
from src.Functionality.Management.pluginManagement import *
from src.Functionality.Display.search import *
from src.Functionality.Analysis.dynamicAnalysis import *
from src.Functionality.Display.displayPointsOfInterests import *
from src.Functionality.Display.displayManagement import *

class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow, self).__init__()
        self.window = Ui_BATT5()
        self.window.setupUi(self)
        self.showMaximized()

        # ---- Main Window --------------------------------------------------------------------------------------------
        self.populateProjectBox()                                                               # display project list
        self.populatePluginFields()                                                             # display plugins
        self.setProject()                                                                       # set current project

        # ---- Menu Bar -----------------------------------------------------------------------------------------------
        self.window.actionNew_Project.setShortcut("Ctrl+N")                                     # open new project
        self.window.actionNew_Project.triggered.connect(self.showNewProject)
        self.window.actionDocumentation.setShortcut("Ctrl+D")                                   # open documentation
        self.window.actionDocumentation.triggered.connect(self.showDocumentationWindow)

        # ---- Analysis Tab --------------------------------------------------------------------------------------------
        self.window.commentSave_button.clicked.connect(self.callSaveComment)                    # save comment
        self.window.commentClear_button.clicked.connect(self.clearComment)                      # clear comment
        self.window.projectNavigator_tree.itemSelectionChanged.connect(self.setProject)         # disp proj properties
        self.window.runStaticAnalysis_button.clicked.connect(self.runStatic)                    # run static
        self.window.poiType_dropdown.currentIndexChanged.connect(self.displayPoi)               # display POI by type
        self.window.runDynamicAnalysis_button.clicked.connect(self.disable)                     # run dynamic
        self.window.radareConsoleIn_lineEdit.returnPressed.connect(self.inputCommand)           # execute r2 cmd
        self.window.expandCollapseAll_check.clicked.connect(self.expandPOI)                     # expand/collapse poi

        self.window.projectNavigator_tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)     # right-click project
        self.window.projectNavigator_tree.customContextMenuRequested.connect(self.rightClickOnProject)

        # ---- Search Functions ----------------------------------------------------------------------------------------
        self.window.projectSearch_lineEdit.textChanged.connect(self.callSearchProject)          # search project list
        self.window.poiSearch_lineEdit.textChanged.connect(self.callSearchPoi)                  # search poi list
        self.window.pluginManagementSearch_lineEdit.textChanged.connect(self.callSearchPluginM) # search plugin list
        self.window.poiManagementSeach_lineEdit.textChanged.connect(self.callSearchPoiM)        # search mngmt poi list

        # ---- Comment Functionality ----------------------------------------------------------------------------------
        self.window.poi_list.itemSelectionChanged.connect(self.callHighlightTree)               # view comment from list
        self.window.viewFunc_tree.currentItemChanged.connect(self.callHighlightList)            # view comment from tree
        self.window.viewString_tree.currentItemChanged.connect(self.callHighlightList)
        self.window.viewVar_tree.currentItemChanged.connect(self.callHighlightList)
        self.window.viewDll_tree.currentItemChanged.connect(self.callHighlightList)

        # ---- Management Tab -----------------------------------------------------------------------------------------
        self.window.dpmPluginStructure_button.clicked.connect(self.showFileExplorer)            # browse plugin struct
        self.window.saveXMLPlugin_button.clicked.connect(self.callSavePluginXML)                # new plugin from xml
        self.window.saveManualPlugin_button.clicked.connect(self.callSavePluginManual)          # new plugin manual
        self.window.dpoimPredefined_button.clicked.connect(self.showFileExplorer_predefined)    # browse poi structure
        self.window.pluginManagement_list.itemSelectionChanged.connect(self.callDisplayPlugin)  # display plugin
        self.window.clearManualPlugin_button.clicked.connect(self.callDeselectPlugin)           # de-select plugin
        self.window.clearXMLPlugin_button.clicked.connect(self.newXMLPluginTemplate)            # clear manual txt
        self.window.savePoi_button.clicked.connect(self.callAddPoiToPlugin)                     # save poi to plugin
        self.window.savePredefPoi_button.clicked.connect(self.callAddPoiToPluginXml)            # save poi to plugin xml
        self.window.addPoiType_dropdown.currentIndexChanged.connect(self.callDisplayPoiFromPlugin)  # disp poi from plugin
        self.window.clearPoiAll_button.clicked.connect(self.newManualPoiTemplate)               # clear manual poi
        self.window.clearPredefPoi_button.clicked.connect(self.newXMLPoiTemplate)               # clear xml poi

        self.window.poiManagement_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)        # delete poi management
        self.window.poiManagement_list.customContextMenuRequested.connect(self.rightClickOnPoi)
        self.window.pluginManagement_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)     # delete plugin
        self.window.pluginManagement_list.customContextMenuRequested.connect(self.rightClickOnPlugin)

        # ---- Other --------------------------------------------------------------------------------------------------
        self.window.switchToHistory_button.clicked.connect(self.switchViews)                    # switch views
        self.window.check_allpoi.stateChanged.connect(self.checkstate_poi)                      # check pois

    def populateProjectBox(self):    # Initialize the project box with all the current projects from database
        projects = getProjects()
        projectTree = []
        for i in range(len(projects)):
            projectTree.append(QTreeWidgetItem([projects[i]]))
        tree = self.window.projectNavigator_tree
        tree.addTopLevelItems(projectTree)

    def setProject(self):       # Changes the project description according to the current project from database
        selected = self.window.projectNavigator_tree.selectedItems()
        text, binaryPath = setCurrentProject(selected) # Get the properties and name of the selected project
        current = setWindowTitle()
        self.setWindowTitle("BATT5 - " + current)
        try:
            self.window.projectNavigator_tree.setCurrentItem(
                self.window.projectNavigator_tree.findItems(current, QtCore.Qt.MatchContains)[0])
        except IndexError:
            pass

        self.window.projectProperties_text.setHtml(text) # Populate the properties box with the current project
        self.window.projectProperties_text_h.setHtml("<b> Current Project </b>: " + current + "<br>" + text)

        if checkStatic(): # Checks if static has already been performed
            self.window.runDynamicAnalysis_button.setEnabled(True)
            self.window.commentSave_button.setEnabled(True)
            self.displayPoi()
        else:
            self.window.runDynamicAnalysis_button.setEnabled(False)
            self.window.commentSave_button.setEnabled(False)
            self.displayPoi()

        self.terminal = Terminal(binaryPath, self.window.radareConsoleIn_lineEdit, self.window.radareConsoleOut_text,
                                 self.window.recentCmd_text) # Set up command prompt
        self.window.recentCmd_text.clear()

    def populatePluginFields(self): # Initialize every field that involve plugins with all the current plugins
        plugins = getPlugins()
        self.window.pluginManagement_list.clear()
        self.window.pluginManagement_list.addItems(plugins)

        self.window.pluginSelection_dropdown.clear()
        self.window.pluginSelection_dropdown.addItem('None')
        self.window.pluginSelection_dropdown.addItems(plugins)

    # ---- Following methods provide all the search functionality in the analysis tab --------------------------
    def callSearchProject(self): # Search functionality for the project box
        try:
            searchProject(str(self.window.projectSearch_lineEdit.text()), self.window.projectNavigator_tree)
            if not self.window.projectSearch_lineEdit.text():
                self.populateProjectBox()
        except AttributeError:
            pass

    def callSearchPoi(self): # Search functionality for the poi box
        try:
            searchPoi(str(self.window.poiSearch_lineEdit.text()), self.window.poi_list,
                      self.window.poiType_dropdown.currentText())
        except AttributeError:
            pass

    def callHighlightTree(self): # for display comment and highlighting
        if self.window.poi_list.selectedItems():
            itemIndex = self.window.poi_list.currentRow()
            currTree = self.getCurrentTree()
            item = currTree.topLevelItem(itemIndex)
            currTree.setCurrentItem(item)
            currTree.scrollToItem(item)

        getComment(self.window.poi_list.currentItem().text(), self.window.poiType_dropdown.currentText(),
                   self.window.comment_text)

    # ---- Following methods are vital for everything revolving static analysis -------------------------------
    def runStatic(self): # runs Static Analysis w/ database stuff
        if self.window.projectNavigator_tree.currentItem():
            if not checkStatic():
                self.window.runDynamicAnalysis_button.setEnabled(True)
                self.window.commentSave_button.setEnabled(True)

                path = getCurrentFilePath() # Get the path of the binary file and run static analysis
                poi = staticAnalysis(path)

                saveStatic(poi) # Save the results of static into the database
                self.displayPoi()
            else:
                self.displayPoi()
        else:
            QMessageBox.question(self, "Error Message: No Project selected",
                                 "A project has not been selected, cannot perform Static Analysis.", QMessageBox.Ok)

    def runDynamic(self): # runs Dynamic analysis with database stuff
        path = getCurrentFilePath()
        poi = staticAnalysis(path)
        funcList = []
        for i in range(len(poi[0])):
            funcList.append(poi[0][i]['name'])

        valueList = historicAnalysis(path, funcList)
        valueList2 = dynamicAnalysis(path, valueList)
        print(valueList2)

        saveDynamic(poi, valueList2)
        self.displayPoi()
        self.enable()

    def displayPoi(self): # Displays POIs in the Analysis box
        self.window.viewFunc_tree.clear()
        self.window.viewString_tree.clear()
        self.window.viewVar_tree.clear()
        self.window.viewDll_tree.clear()
        self.window.poi_list.clear()

        poi = self.window.poiType_dropdown.currentText()
        content = getPoi(poi)
        filterContent = getFilterPoi(self.window.pluginSelection_dropdown.currentText())
        currTree = self.getCurrentTree()
        if poi == 'Function': # switch tree
            self.window.viewPoi_stack.setCurrentIndex(0)
            if self.window.changeViews_stack.currentIndex() == 1:
                self.disableCheck()
            else:
                self.enableCheck()
        else:
            self.disableCheck()
            if poi == 'String':
                self.window.viewPoi_stack.setCurrentIndex(1)
            elif poi == 'Variable':
                self.window.viewPoi_stack.setCurrentIndex(2)
            elif poi == 'DLL':
                self.window.viewPoi_stack.setCurrentIndex(3)
        if self.window.pluginSelection_dropdown.currentText() == 'None': # call function to display poi's
            displayPoiController(poi, currTree, self.window.poi_list, content, self.window.comment_text)
        else:
            displayFilteredPoiController(poi, currTree, self.window.poi_list, filterContent, content,
                                         self.window.comment_text)

    # ---- Following methods are vital for everything revolving dynamic analysis --------------------------------
    def inputCommand(self): # Takes input from user and passes it to the terminal
        cmd_in = str(self.window.radareConsoleIn_lineEdit.text())
        self.terminal.processInput(cmd_in)
        self.window.radareConsoleIn_lineEdit.clear()

    # ---- Following methods are for deleting a project from the database -------------------
    def rightClickOnProject(self, point): # Provides the functionality to delete a project by right clicking on it
        index = self.window.projectNavigator_tree.indexAt(point) # Infos about the node selected.

        if not index.isValid():
            return

        menu = QtWidgets.QMenu() # We build the menu
        menu.addAction("Delete", self.showConfirmationDeleteProject)
        menu.exec_(self.window.projectNavigator_tree.mapToGlobal(point))

    def callDeleteProject(self): # Deletes a project
        if self.window.projectNavigator_tree.currentItem():
            project = self.window.projectNavigator_tree.currentItem().text(0)
            deleteAProject(project)

            self.window.projectNavigator_tree.clear()
            self.populateProjectBox()

    # ---- Following methods are for calling and showing the different windows in the analysis tab ------------------
    def showNewProject(self): # Shows NewProject window
        self.ui = ProjectWindow()
        if self.ui.exec_() == ProjectWindow.Accepted:
            self.window.projectNavigator_tree.clear()
            self.populateProjectBox()
            self.window.projectNavigator_tree.setCurrentItem(
                self.window.projectNavigator_tree.topLevelItem(
                    self.window.projectNavigator_tree.topLevelItemCount() - 1))

    def showConfirmationDeleteProject(self): # Shows confirmation to delete project
        name = self.window.projectNavigator_tree.currentItem().text(0)
        choice = QMessageBox.question(self, 'Warning', "Are you sure you want to delete project: {}?".format(name),
                                      QMessageBox.Yes | QMessageBox.Cancel)
        if choice == QMessageBox.Yes:
            self.callDeleteProject()

    def showErrFile(self): # Shows ErrFile window
        QMessageBox.question(self, "Error Message: File Specified",
                             "A project is associated with one binary file and cannot be saved \n"
                             "without a binary file. Please provide a binary file.", QMessageBox.Ok)

    def showDocumentationWindow(self): # Shows Documentation window
        self.ui = DocumentationWindow()
        self.ui.exec_()

    # ---- Following methods are for misc. stuff in the analysis tab ---------------------------------------
    def callSaveComment(self): # Save a comment in the currently clicked poi from the poi list
        if self.window.poi_list.currentItem():
            currTree = self.getCurrentTree()
            saveComment(self.window.comment_text.toPlainText(), self.window.poi_list.currentItem().text(),
                        self.window.poiType_dropdown.currentText())
            if self.window.comment_text.toPlainText() == "":
                self.window.poi_list.currentItem().setIcon(QIcon())
                removeIconTree(currTree, self.window.poi_list.currentItem())
            else:
                addIcon(self.window.poi_list.currentItem())
                addIconTree(currTree, self.window.poi_list.currentItem())

    def clearComment(self): # Clear comment text
        self.window.comment_text.clear()

    def enableCheck(self): # enable checkbox
        self.window.check_allpoi.setCheckable(True)

    def disableCheck(self): # disable checkbox
        self.window.check_allpoi.setCheckable(False)

    def checkstate_poi(self): # Check or Uncheck poi List
        for i in range(self.window.poi_list.count()):
            item = self.window.poi_list.item(i)
            if not item.isHidden():
                if self.window.check_allpoi.isChecked():
                    item.setCheckState(QtCore.Qt.Checked)
                elif self.window.check_allpoi.checkState() == 0:
                    item.setCheckState(QtCore.Qt.Unchecked)

    def switchViews(self): # From current to history
        text = self.window.switchToHistory_button.text()
        if text == 'Switch to History View':
            self.window.changeViews_stack.setCurrentIndex(1)
            self.window.switchToHistory_button.setText('Switch to Current View')
            self.disableCheck()
        else:
            self.window.changeViews_stack.setCurrentIndex(0)
            self.window.switchToHistory_button.setText('Switch to History View')
            self.enableCheck()

    def callHighlightList(self):
        currTree = self.getCurrentTree()
        try:
            highlightList(currTree, self.window.poi_list)
        except AttributeError:
            pass

    def disable(self):
        self.window.viewFunc_tree.clear()
        self.window.central_tabs.setEnabled(False)
        self.window.menubar.setDisabled(False)
        QTimer.singleShot(1000, lambda: self.runDynamic())

    def enable(self):
        self.window.central_tabs.setDisabled(False)
        self.window.menubar.setDisabled(False)

    def expandPOI(self):
        currTree = self.getCurrentTree()
        if self.window.expandCollapseAll_check.checkState():
            currTree.expandAll()
        else:
            currTree.collapseAll()

    # ---- Following methods provide all the search functionality in the management tab --------------------------
    def callSearchPluginM(self):
        try:
            searchPluginM(str(self.window.pluginManagementSearch_lineEdit.text()), self.window.pluginManagement_list)
        except AttributeError:
            pass

    def callSearchPoiM(self):
        try:
            searchPoiM(str(self.window.poiManagementSeach_lineEdit.text()), self.window.poiManagement_list,
                       self.window.addPoiType_dropdown.currentText(),
                       self.window.pluginManagement_list.currentItem().text())
        except AttributeError:
            pass

    # ---- Following methods are for saving/creating a new plugin or poi based on predefined or manual input -------
    def callSavePluginXML(self): # Save a predefined plugin into the database
        savePluginXML(self, self.window.dpmPluginStructure_lineEdit)
        self.populatePluginFields()
        self.newXMLPluginTemplate()

    def callSavePluginManual(self): # Save a manually inputted plugin into the database
        if self.window.saveManualPlugin_button.text() == 'Save':
            savePluginManual(self, self.window.dpmPluginName_lineEdit, self.window.dpmPluginDesc_lineEdit)
        elif self.window.saveManualPlugin_button.text() == 'Update Plugin':
            modifyPlugin(self, self.window.pluginManagement_list.currentItem().text(),
                         self.window.dpmPluginName_lineEdit.text(), self.window.dpmPluginDesc_lineEdit.text())
        self.populatePluginFields()
        self.callDeselectPlugin()

    def newXMLPluginTemplate(self): # Clears the labels that are used for creating a new predefined plugin to create one
        self.window.dpmPluginStructure_lineEdit.clear()
        self.window.pluginManagement_list.clearSelection()

    def callDeselectPlugin(self): # Clears the labels that are used for creating a new plugin to create a new plugin
        deselectPlugin(self.window.dpmPluginName_lineEdit, self.window.dpmPluginDesc_lineEdit,
                       self.window.pluginManagement_list, self.window.pluginEditingStatus_label,
                       self.window.addPoiXML_label, self.window.addPoiManual_label, self.window.saveManualPlugin_button,
                       self.window.clearManualPlugin_button, self.window.poiManagement_list,
                       self.window.addPluginXml_frame)

    def newXMLPoiTemplate(self): # Clears the labels that are used for creating a new predefined poi set
        self.window.dpoimPredefined_lineEdit.clear()

    def newManualPoiTemplate(self): # Clears the labels that are used for creating a new predefined poi
        self.window.addPoiName_lineEdit.clear()

    # ---- Following methods are for displaying a plugin and a plugin's poi in the management tab ----------------
    def callDisplayPlugin(self): # Displays a detailed view of a plugin when it is clicked
        name, description, poi = getCurrentPlugin(self.window.pluginManagement_list.currentItem().text())
        displayPlugin(name, description, self.window.pluginManagement_list, self.window.addPoiType_dropdown,
              self.window.pluginEditingStatus_label, self.window.addPoiXML_label, self.window.addPoiManual_label,
              self.window.dpmPluginName_lineEdit, self.window.dpmPluginDesc_lineEdit,
              self.window.saveManualPlugin_button, self.window.clearManualPlugin_button, self.window.addPluginXml_frame)
        self.callDisplayPoiFromPlugin()

    def callDisplayPoiFromPlugin(self): # Displays all pois associated with the clicked plugin
        displayPoiFromPlugin(self.window.poiManagement_list, self.window.pluginManagement_list,
                             self.window.addPoiType_dropdown, self.window.addPoiManual_label)

    # ---- Following methods are for deleting a plugin or poi from the database in the management tab --------------
    def rightClickOnPlugin(self, point): # Provides the functionality to delete a plugin by right clicking on it
        index = self.window.pluginManagement_list.indexAt(point) # Infos about the node selected.
        if not index.isValid():
            return
        menu = QtWidgets.QMenu() # We build the menu.
        menu.addAction("Delete", self.showConfirmationDeletePlugin)
        menu.exec_(self.window.pluginManagement_list.mapToGlobal(point))

    def callDeletePlugin(self): # Deletes a plugin
        if self.window.pluginManagement_list.currentItem():
            plugin = self.window.pluginManagement_list.currentItem().text()
            deleteAPlugin(plugin)
            self.window.pluginManagement_list.clear()
            self.window.pluginSelection_dropdown.clear()
            self.populatePluginFields()
            self.callDeselectPlugin()

    def rightClickOnPoi(self, point): # Provides functionality to delete a poi from a plugin by right clicking on it
        index = self.window.poiManagement_list.indexAt(point) # Infos about the node selected.
        if not index.isValid():
            return
        menu = QtWidgets.QMenu() # We build the menu.
        menu.addAction("Delete", self.showConfirmationDeletePoi)
        menu.exec_(self.window.poiManagement_list.mapToGlobal(point))

    def callDeletePoiFromPlugin(self): # Deletes a poi from the specified plugin
        if self.window.poiManagement_list.currentItem():
            poi = self.window.poiManagement_list.currentItem().text()
            plugin = self.window.pluginManagement_list.currentItem().text()
            pluginDict = getCurrentPluginInfo(plugin)
            modifiedPlugin = removePoiFromPlugin(pluginDict, poi)
            deleteAPoiFromPlugin(plugin, modifiedPlugin)
            self.window.poiManagement_list.clear()
            self.callDisplayPoiFromPlugin()

    # ---- Following methods are for calling and showing the different windows in the management tab -----------------
    def showConfirmationDeletePlugin(self): # Show the confirmation window when deleting a plugin
        name = self.window.pluginManagement_list.currentItem().text()
        choice = QMessageBox.question(self, 'Warning',
                                      "Are you sure you want to delete plugin: {}?".format(name),
                                      QMessageBox.Yes | QMessageBox.Cancel)
        if choice == QMessageBox.Yes:
            self.callDeletePlugin()

    def showConfirmationDeletePoi(self): # Show the confirmation window when deleting a poi
        poi = self.window.poiManagement_list.currentItem().text()
        plugin = self.window.pluginManagement_list.currentItem().text()
        choice = QMessageBox.question(self, 'Warning',
                                      "Are you sure you want to delete poi {} ".format(poi) + "from: {}?".format(
                                          plugin),
                                      QMessageBox.Yes | QMessageBox.Cancel)
        if choice == QMessageBox.Yes:
            self.callDeletePoiFromPlugin()

    def showFileExplorer(self): # Open up file explorer to select a file for Plugin predefined line edit
        path = Path(__file__).parents[2].as_posix() + '/Configurations/Sample Configurations'
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File', path, 'XML Files (*.xml)', options=options)
        self.window.dpmPluginStructure_lineEdit.setText(name)

    def showFileExplorer_predefined(self):     # Open up file explorer to select a file for Poi predefined line edit
        path = Path(__file__).parents[2].as_posix() + '/Configurations/Sample Configurations'
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File', path, 'XML Files (*.xml)', options=options)
        self.window.dpoimPredefined_lineEdit.setText(name)

    # ---- Following methods are for misc. stuff in the management tab --------------------------------------------
    def callAddPoiToPlugin(self):
        try:
            addPoiToPlugin(self, self.window.addPoiName_lineEdit.text(),
                           self.window.addPoiType_dropdown.currentText(),
                           self.window.pluginManagement_list.currentItem().text())
            self.callDisplayPoiFromPlugin()
        except:
            QMessageBox.question(self, "Error: Invalid Input", "You must have a plugin selected", QMessageBox.Ok)
        self.window.addPoiName_lineEdit.clear()

    def callAddPoiToPluginXml(self):
        try:
            addPoiToPluginXml(self, self.window.dpoimPredefined_lineEdit.text(),
                              self.window.pluginManagement_list.currentItem().text())
            self.callDisplayPoiFromPlugin()
        except:
            QMessageBox.question(self, "Error: Invalid Input", "You must have a plugin selected", QMessageBox.Ok)
        self.window.dpoimPredefined_lineEdit.clear()

    def getCurrentTree(self):
        poiType = self.window.poiType_dropdown.currentText()
        if poiType == 'Function':
            return self.window.viewFunc_tree
        elif poiType == 'String':
            return self.window.viewString_tree
        elif poiType == 'Variable':
            return self.window.viewVar_tree
        elif poiType == 'DLL':
            return self.window.viewDll_tree

# ------------------------------------------------ MAIN ---------------------------------------------------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
