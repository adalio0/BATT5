# ! /usr/bin/env python3.

from PyQt5 import QtWidgets
from PyQt5.QtCore import QTimer
from src.GUI.python_files.BATT5_GUI import Ui_BATT5
from src.Functionality.newProject import ProjectWindow
from src.Functionality.documentation import DocumentationWindow
from src.Functionality.staticAnalysis import staticAnalysis, historicAnalysis
from src.Functionality.radareTerminal import Terminal
from src.Functionality.pluginManagement import *
from src.Functionality.database import *
from src.Functionality.search import *
from src.Functionality.dynamicAnalysis import *
from src.Functionality.displayPointsOfInterests import *
from src.Functionality.displayManagement import *

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
        self.window.actionDocumentation.triggered.connect(self.showDocumentationWindow)         #\

        # ---- Analysis Tab --------------------------------------------------------------------------------------------
        self.window.commentSave_button.clicked.connect(self.callSaveComment)                    # save comment
        self.window.commentClear_button.clicked.connect(self.clearComment)                      # clear comment
        self.window.projectNavigator_tree.itemSelectionChanged.connect(self.setProject)         # disp proj properties
        self.window.runStaticAnalysis_button.clicked.connect(self.runStatic)                    # run static
        self.window.runDynamicAnalysis_button.clicked.connect(self.disable)                     # run dynamic
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

        # ---- Filters ------------------------------------------------------------------------------------------------
        self.window.poiType_dropdown.currentIndexChanged.connect(self.displayPoi)               # display POI by type

        # ---- Console ------------------------------------------------------------------------------------------------
        self.window.radareConsoleIn_lineEdit.returnPressed.connect(self.inputCommand)           # execute r2 cmd

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

        # Get the properties and name of the selected project
        text, binaryPath = setCurrentProject(selected)
        current = setWindowTitle()
        self.setWindowTitle("BATT5 - " + current)
        try:
            self.window.projectNavigator_tree.setCurrentItem(
                self.window.projectNavigator_tree.findItems(current, QtCore.Qt.MatchContains)[0])
        except IndexError:
            pass

        # Populate the properties box with the current project
        self.window.projectProperties_text.setHtml(text)
        self.window.projectProperties_text_h.setHtml("<b> Current Project </b>: " + current + "<br>" + text)

        # Checks if static has already been performed, if so unlock dynamic and display poi
        if checkStatic():
            self.window.runDynamicAnalysis_button.setEnabled(True)
            self.window.commentSave_button.setEnabled(True)
            self.displayPoi()
        else:
            self.window.runDynamicAnalysis_button.setEnabled(False)
            self.window.commentSave_button.setEnabled(False)
            self.displayPoi()

        # Set up command prompt
        self.terminal = Terminal(binaryPath, self.window.radareConsoleIn_lineEdit, self.window.radareConsoleOut_text,
                                 self.window.recentCmd_text)
        self.window.recentCmd_text.clear()

    # Initialize every field that involve plugins with all the current plugins from database
    def populatePluginFields(self):
        plugins = getPlugins()

        # plugin management list
        self.window.pluginManagement_list.clear()
        self.window.pluginManagement_list.addItems(plugins)

        # plugin dropdown menu
        self.window.pluginSelection_dropdown.clear()
        self.window.pluginSelection_dropdown.addItem('None')
        self.window.pluginSelection_dropdown.addItems(plugins)

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
            searchPoi(str(self.window.poiSearch_lineEdit.text()), self.window.poi_list,
                      self.window.poiType_dropdown.currentText())
        except AttributeError:
            pass

    # for display comment and highlighting
    def callHighlightTree(self):
        if self.window.poi_list.selectedItems():
            itemIndex = self.window.poi_list.currentRow()
            currTree = self.getCurrentTree()
            item = currTree.topLevelItem(itemIndex)
            currTree.setCurrentItem(item)
            currTree.scrollToItem(item)

        getComment(self.window.poi_list.currentItem().text(), self.window.poiType_dropdown.currentText(),
                   self.window.comment_text)

    # ---- Following methods are vital for everything revolving static analysis -------------------------------
    # runs Static Analysis w/ database stuff
    def runStatic(self):
        if self.window.projectNavigator_tree.currentItem():
            if not checkStatic():
                self.window.runDynamicAnalysis_button.setEnabled(True)
                self.window.commentSave_button.setEnabled(True)

                # Get the path of the binary file and run static analysis
                path = getCurrentFilePath()
                poi = staticAnalysis(path)

                # Save the results of static into the database
                saveStatic(poi)
                self.displayPoi()
            else:
                self.displayPoi()
        else:
            QMessageBox.question(self, "Error Message: No Project selected",
                                 "A project has not been selected, cannot perform Static Analysis.", QMessageBox.Ok)

    # runs Dynamic analysis with database stuff
    def runDynamic(self):
        path = getCurrentFilePath()
        poi = staticAnalysis(path)
        funcList = []
        for i in range(len(poi[0])):
            funcList.append(poi[0][i]['name'])

        valueList = historicAnalysis(path,funcList)
        valueList2 = dynamicAnalysis(path,valueList)
        print(valueList2)

        saveDynamic(poi, valueList2)
        self.displayPoi()
        self.enable()

    # Displays POIs in the Analysis box
    def displayPoi(self):
        self.window.viewFunc_tree.clear()
        self.window.viewString_tree.clear()
        self.window.viewVar_tree.clear()
        self.window.viewDll_tree.clear()
        self.window.poi_list.clear()

        poi = self.window.poiType_dropdown.currentText()
        content = getPoi(poi)
        filterContent = getFilterPoi(self.window.pluginSelection_dropdown.currentText())
        currTree = self.getCurrentTree()
        # switch tree
        if poi == 'Function':
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
        # call function to display poi's
        if self.window.pluginSelection_dropdown.currentText() == 'None':
            displayPoiController(poi, currTree, self.window.poi_list, content, self.window.comment_text)
        else:
            displayFilteredPoiController(poi, currTree, self.window.poi_list, filterContent, content, self.window.comment_text)

    # ---- Following methods are vital for everything revolving dynamic analysis --------------------------------
    # Takes input from user and passes it to the terminal
    def inputCommand(self):
        cmd_in = str(self.window.radareConsoleIn_lineEdit.text())
        self.terminal.processInput(cmd_in)
        self.window.radareConsoleIn_lineEdit.clear()

    # ---- Following methods are for deleting a project from the database -------------------
    # Provides the functionality to delete a project by right clicking on it
    def rightClickOnProject(self, point):
        # Infos about the node selected.
        index = self.window.projectNavigator_tree.indexAt(point)

        if not index.isValid():
            return

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
            self.window.projectNavigator_tree.setCurrentItem(
                self.window.projectNavigator_tree.topLevelItem(
                    self.window.projectNavigator_tree.topLevelItemCount() - 1))

    # Shows confirmation to delete project
    def showConfirmationDeleteProject(self):
        name = self.window.projectNavigator_tree.currentItem().text(0)
        choice = QMessageBox.question(self, 'Warning', "Are you sure you want to delete project: {}?".format(name),
                                      QMessageBox.Yes | QMessageBox.Cancel)
        if choice == QMessageBox.Yes:
            self.callDeleteProject()

    # Shows ErrFile window
    def showErrFile(self):
        QMessageBox.question(self, "Error Message: File Specified",
                             "A project is associated with one binary file and cannot be saved \n"
                             "without a binary file. Please provide a binary file.", QMessageBox.Ok)

    # Shows Documentation window
    def showDocumentationWindow(self):
        self.ui = DocumentationWindow()
        self.ui.exec_()

    # Open the file explorer to select a file for the output window
    def showFileExplorer_outFuncSource(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmOutFuncSource_lineEdit.setText(name)

    # ---- Following methods are for misc. stuff in the analysis tab ---------------------------------------
    # Save a comment in the currently clicked poi from the poi list
    def callSaveComment(self):
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
        for i in range(self.window.poi_list.count()):
            item = self.window.poi_list.item(i)
            if not item.isHidden():
                if self.window.check_allpoi.isChecked():
                    item.setCheckState(QtCore.Qt.Checked)
                elif self.window.check_allpoi.checkState() == 0:
                    item.setCheckState(QtCore.Qt.Unchecked)

    # From current to history
    def switchViews(self):
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

    # Save a predefined plugin into the database
    def callSavePluginXML(self):
        savePluginXML(self, self.window.dpmPluginStructure_lineEdit)
        self.populatePluginFields()
        self.newXMLPluginTemplate()

    # Save a manually inputted plugin into the database
    def callSavePluginManual(self):
        if self.window.saveManualPlugin_button.text() == 'Save':
            savePluginManual(self, self.window.dpmPluginName_lineEdit, self.window.dpmPluginDesc_lineEdit,)
        elif self.window.saveManualPlugin_button.text() == 'Update Plugin':
            modifyPlugin(self, self.window.pluginManagement_list.currentItem().text(),
                         self.window.dpmPluginName_lineEdit.text(), self.window.dpmPluginDesc_lineEdit.text())
        self.populatePluginFields()
        self.callDeselectPlugin()

    # Clears the labels that are used for creating a new predefined plugin to create a new plugin
    def newXMLPluginTemplate(self):
        self.window.dpmPluginStructure_lineEdit.clear()
        self.window.pluginManagement_list.clearSelection()

    # Clears the labels that are used for creating a new plugin to create a new plugin
    def callDeselectPlugin(self):
        deselectPlugin(self.window.dpmPluginName_lineEdit, self.window.dpmPluginDesc_lineEdit,
                       self.window.pluginManagement_list, self.window.pluginEditingStatus_label,
                       self.window.addPoiXML_label, self.window.addPoiManual_label, self.window.saveManualPlugin_button,
                       self.window.clearManualPlugin_button, self.window.poiManagement_list,
                       self.window.addPluginXml_frame)

    # Clears the labels that are used for creating a new predefined poi set to create a new poi set
    def newXMLPoiTemplate(self):
        self.window.dpoimPredefined_lineEdit.clear()

    # Clears the labels that are used for creating a new predefined poi to create a new poi
    def newManualPoiTemplate(self):
        self.window.addPoiName_lineEdit.clear()

    # ---- Following methods are for displaying a plugin and a plugin's poi in the management tab ----------------
    # Displays a detailed view of a plugin when it is clicked
    def callDisplayPlugin(self):
        name, description, poi = getCurrentPlugin(self.window.pluginManagement_list.currentItem().text())
        displayPlugin(name, description, self.window.pluginManagement_list, self.window.addPoiType_dropdown,
              self.window.pluginEditingStatus_label, self.window.addPoiXML_label, self.window.addPoiManual_label,
              self.window.dpmPluginName_lineEdit, self.window.dpmPluginDesc_lineEdit,
              self.window.saveManualPlugin_button, self.window.clearManualPlugin_button, self.window.addPluginXml_frame)
        self.callDisplayPoiFromPlugin()

    # Displays all pois associated with the clicked plugin
    def callDisplayPoiFromPlugin(self):
        displayPoiFromPlugin(self.window.poiManagement_list, self.window.pluginManagement_list,
                             self.window.addPoiType_dropdown, self.window.addPoiManual_label)

    # ---- Following methods are for deleting a plugin or poi from the database in the management tab --------------

    # Provides the functionality to delete a plugin by right clicking on it
    def rightClickOnPlugin(self, point):
        # Infos about the node selected.
        index = self.window.pluginManagement_list.indexAt(point)
        if not index.isValid():
            return
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
            self.callDeselectPlugin()

    # Provides functionality to delete a poi from a plugin by right clicking on it
    def rightClickOnPoi(self, point):
        # Infos about the node selected.
        index = self.window.poiManagement_list.indexAt(point)
        if not index.isValid():
            return
        # We build the menu.
        menu = QtWidgets.QMenu()
        menu.addAction("Delete", self.showConfirmationDeletePoi)
        menu.exec_(self.window.poiManagement_list.mapToGlobal(point))

    # Deletes a poi from the specified plugin
    def callDeletePoiFromPlugin(self):
        if self.window.poiManagement_list.currentItem():
            poi = self.window.poiManagement_list.currentItem().text()
            plugin = self.window.pluginManagement_list.currentItem().text()
            pluginDict = getCurrentPluginInfo(plugin)
            modifiedPlugin = removePoiFromPlugin(pluginDict, poi)
            deleteAPoiFromPlugin(plugin, modifiedPlugin)
            self.window.poiManagement_list.clear()
            self.callDisplayPoiFromPlugin()

    # ---- Following methods are for calling and showing the different windows in the management tab -----------------

    # Show the confirmation window when deleting a plugin
    def showConfirmationDeletePlugin(self):
        name = self.window.pluginManagement_list.currentItem().text()
        choice = QMessageBox.question(self, 'Warning',
                                      "Are you sure you want to delete plugin: {}?".format(name),
                                      QMessageBox.Yes | QMessageBox.Cancel)
        if choice == QMessageBox.Yes:
            self.callDeletePlugin()

    # Show the confirmation window when deleting a poi
    def showConfirmationDeletePoi(self):
        poi = self.window.poiManagement_list.currentItem().text()
        plugin = self.window.pluginManagement_list.currentItem().text()
        choice = QMessageBox.question(self, 'Warning',
                                      "Are you sure you want to delete poi {} ".format(poi) + "from: {}?".format(
                                          plugin),
                                      QMessageBox.Yes | QMessageBox.Cancel)
        if choice == QMessageBox.Yes:
            self.callDeletePoiFromPlugin()

    # Open up file explorer to select a file for Plugin predefined line edit
    def showFileExplorer(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.dpmPluginStructure_lineEdit.setText(name)

    # Open up file explorer to select a file for Poi predefined line edit
    def showFileExplorer_predefined(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
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
            currTree = self.window.viewFunc_tree
        elif poiType == 'String':
            currTree = self.window.viewString_tree
        elif poiType == 'Variable':
            currTree = self.window.viewVar_tree
        elif poiType == 'DLL':
            currTree = self.window.viewDll_tree
        return currTree

# ------------------------------------------------ MAIN ---------------------------------------------------------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
