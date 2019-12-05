from PyQt5 import QtCore
from PyQt5.QtGui import QIcon, QColor
from PyQt5.QtWidgets import *
from src.Functionality.database import getProjects, getComment
from src.Functionality.database import getPlugins
from src.Functionality.database import getFilterPoi


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
        projectNavigator_tree.clear()
        projectNavigator_tree.addTopLevelItems(projects)
    else:
        projectNavigator_tree.clear()


# Search functionality for the poi box
def searchPoi(search, poi_list, poi_type):
    result = poi_list.findItems(search, QtCore.Qt.MatchContains)
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
                poi_list.item(i).setHidden(False)
                j += 1
            else:
                poi_list.item(i).setHidden(True)
    else:
        for i in range(poi_list.count()):
            poi_list.item(i).setHidden(False)


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
        pluginManagement_list.clear()
        pluginManagement_list.addItems(plugin)
    else:
        plugins = getPlugins()
        pluginManagement_list.clear()
        pluginManagement_list.addItems(plugins)


def searchPoiM(search, poiManagement_list, poiType, plugin):
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
        poiManagement_list.clear()
        poiManagement_list.addItems(poi)
    else:
        pois = []
        poiType = poiType.lower()
        poiFromPlugin = getFilterPoi(plugin)
        for i in range(len(poiFromPlugin[poiType])):
            pois.append(poiFromPlugin[poiType][i]['name'])
        poiManagement_list.clear()
        poiManagement_list.addItems(pois)


def searchDocumentation(search, document_list):
    result = document_list.findItems(search, QtCore.Qt.MatchContains)
    item = ''
    j = 0

    if search:
        for i in range(document_list.count()):
            try:
                item = QListWidgetItem(result[j])
            except IndexError:
                pass
            if item.text() in document_list.item(i).text():
                document_list.item(i).setHidden(False)
                j += 1
            else:
                document_list.item(i).setHidden(True)
    else:
        for i in range(document_list.count()):
            document_list.item(i).setHidden(False)


def highlightList(view_tree, poi_list):
    item = view_tree.currentItem()
    treeRow = view_tree.indexOfTopLevelItem(item)
    if treeRow != -1:
        listItem = poi_list.item(treeRow)
        poi_list.setCurrentItem(listItem)
        poi_list.scrollToItem(listItem)


def addIcon(poi):
    poi.setIcon(QIcon(r"comment-24px.svg"))

def addIconTree(treeType, currentListItem):
    root = treeType.invisibleRootItem()
    child_count = root.childCount()
    for i in range(child_count):
        item = root.child(i)
        if currentListItem.text() == item.text(0):
            item.setIcon(0,QIcon(r"comment-24px.svg"))

def displayIconTree(treeType,poiName):
    root = treeType.invisibleRootItem()
    child_count = root.childCount()
    for i in range(child_count):
        item = root.child(i)
        if poiName == item.text(0):
            item.setIcon(0, QIcon(r"comment-24px.svg"))

def removeIconTree(treeType, currentListItem):
    root = treeType.invisibleRootItem()
    child_count = root.childCount()
    for i in range(child_count):
        item = root.child(i)
        if currentListItem.text() == item.text(0):
            item.setIcon(0,QIcon())

def highlightCell(cell):
    cell.setBackground(QColor(255, 240, 189))
