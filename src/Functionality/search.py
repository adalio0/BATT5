from PyQt5 import QtCore
from PyQt5.QtWidgets import *
from src.Functionality.database import getProjects
from src.Functionality.database import getPlugins

# Search functionality for the project box
def searchProject(search, projectNavigator_tree):
    result = projectNavigator_tree.findItems(search, QtCore.Qt.MatchContains)

    projects = []
    item = ''
    j = 0
    if search:
        for i in range(projectNavigator_tree.topLevelItemCount()):
            try:
                item = result[j]
            except IndexError:
                pass
            if item.text(0) in projectNavigator_tree.topLevelItem(i).text(0):
                projects.append(QTreeWidgetItem([item.text(0)]))
                child_text = item.child(0).text(0)
                child = QTreeWidgetItem(projects[len(projects) - 1])
                child.setText(0, child_text)
                j += 1
        tree = projectNavigator_tree
        tree.clear()
        tree.addTopLevelItems(projects)
    else:
        tree = projectNavigator_tree
        tree.clear()
        projects = getProjects()
        projectNavigator_tree.addTopLevelItems(projects)

# Search functionality for the poi box
def searchPoi(search, poi_list):
    result = poi_list.findItems(search, QtCore.Qt.MatchContains)

    poi = []
    item = ''

    j = 0
    if search:
        for i in range(poi_list.count()):
            try:
                item = result[j]
            except IndexError:
                pass
            if item.text() in poi_list.item(i).text():
                poi.append(item.text())
                j += 1
        list = poi_list
        list.clear()
        list.addItems(poi)
    else:
        list = poi_list
        list.clear()
        # displayAll()

def searchPluginM(search, pluginManagement_list):
    result = pluginManagement_list.findItems(search, QtCore.Qt.MatchContains)

    plugin = []
    item = ''

    j = 0
    if search:
        for i in range(pluginManagement_list.count()):
            try:
                item = result[j]
            except IndexError:
                pass
            if item.text() in pluginManagement_list.item(i).text():
                plugin.append(item.text())
                j += 1
        list = pluginManagement_list
        list.clear()
        list.addItems(plugin)
    else:
        list = pluginManagement_list
        list.clear()
        plugins = getPlugins()
        pluginManagement_list.addItems(plugins)

def searchPoiM(search, poiManagement_list):
    result = poiManagement_list.findItems(search, QtCore.Qt.MatchContains)

    poi = []
    item = ''

    j = 0
    if search:
        for i in range(poiManagement_list.count()):
            try:
                item = result[j]
            except IndexError:
                pass
            if item.text() in poiManagement_list.item(i).text():
                poi.append(item.text())
                j += 1
        list = poiManagement_list
        list.clear()
        list.addItems(poi)
    else:
        list = poiManagement_list
        list.clear()
        # method to call all pois

# highlight table widget when poi is selected from poi list
def highlightTable(poi, POI_tableWidget):
    POI_tableWidget.clearSelection()
    tablePoi = POI_tableWidget.findItems(poi, QtCore.Qt.MatchContains)

    for item in tablePoi:
        item.setSelected(True)
