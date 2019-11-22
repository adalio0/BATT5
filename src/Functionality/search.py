from PyQt5 import QtCore
from PyQt5.QtGui import QIcon, QColor
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
                j += 1
        tree = projectNavigator_tree
        tree.clear()
        tree.addTopLevelItems(projects)
    else:
        tree = projectNavigator_tree
        tree.clear()


# Search functionality for the poi box
def searchPoi(search, poi_list,poi_type):
    result = poi_list.findItems(search, QtCore.Qt.MatchContains)

    list = poi_list
    poi = []
    item = ''

    j = 0

    if search:
        for i in range(poi_list.count()):
            try:
                item = QListWidgetItem(result[j])
                if poi_type == "Function":
                    item.setCheckState(QtCore.Qt.Checked)

            except IndexError:
                pass
            if item.text() in poi_list.item(i).text():
                poi.append(item)
                j += 1
        list.clear()
        for i in poi:
            list.addItem(i)
    else:
        list = poi_list
        list.clear()


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
        if item.text() == poi:
            item.setSelected(True)
            POI_tableWidget.setCurrentItem(item)
            return


def HighlightList(poi, poi_list):
    poi_list.clearSelection()
    list_of_pois = poi_list.findItems(poi, QtCore.Qt.MatchContains)

    for item in list_of_pois:
        if item.text() == poi:
            item.setSelected(True)
            poi_list.setCurrentItem(item)
            return


def addIcon(poi):
    poi.setIcon(QIcon(r"comment-24px.svg"))


def highlightCell(cell):
    cell.setBackground(QColor(255, 240, 189))
