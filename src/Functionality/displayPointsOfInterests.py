from PyQt5 import QtCore
from PyQt5.QtWidgets import QTreeWidgetItem, QListWidgetItem

from src.Functionality.database import getComment
from src.Functionality.search import addIcon


# Displays the functions extracted from Static Analysis in Analysis box and POI box
def displayFunctions(view_tree, poi_list, content, comment_text):
    funcTree = []
    for i in range(len(content)):
        parent = ''
        children = []
        if 'name' in content[i]:
            parent = QTreeWidgetItem([content[i]['name']])
        if 'signature' in content[i]:
            item = QTreeWidgetItem(parent, ["Signature: " + content[i]['signature']])
            item.setToolTip(0, "Signature: " + content[i]['signature'])
            children.append(item)
        if 'parameters' in content[i]:
            params = []
            paramData = []
            for j in range(len(content[i]['parameters'])):
                params.append(QTreeWidgetItem(children[len(children) - 1],
                                              ["Arg " + str(j + 1) + ": " + content[i]['parameters'][j][
                                                  'name']]))
                paramData.append(QTreeWidgetItem(params[len(params) - 1], ["Type: " + content[i]['parameters'][j]['type']]))
                paramData.append(QTreeWidgetItem(params[len(params) - 1], ["Value: " + content[i]['parameters'][j]['value']]))
            children.append(params)
            children.append(paramData)
        if 'locals' in content[i]:
            children.append(QTreeWidgetItem(parent, ["Local vars:"]))

            local = []
            localData = []
            for j in range(len(content[i]['locals'])):
                local.append(QTreeWidgetItem(children[len(children) - 1], [
                    "Local " + str(j + 1) + ": " + content[i]['locals'][j]['name']]))
                localData.append(QTreeWidgetItem(local[len(local)-1],  ["Type: " + content[i]['locals'][j]['type']]))
                localData.append(QTreeWidgetItem(local[len(local) - 1], ["Value: " + content[i]['locals'][j]['value']]))
            children.append(local)
            children.append(localData)
        if 'returnType' in content[i]:
            children.append(QTreeWidgetItem(parent, ["Return Type: " + content[i]['returnType']]))
        if 'returnValue' in content[i]:
            children.append(QTreeWidgetItem(parent, ["Return Value: " + content[i]['returnValue'] + "\n"]))

        item = QListWidgetItem(content[i]['name'])
        # set icon
        if getComment(content[i]['name'], "Function", comment_text):
            addIcon(item)
        item.setCheckState(QtCore.Qt.Checked)
        poi_list.addItem(item)
        funcTree.append(parent)
    view_tree.addTopLevelItems(funcTree)
    view_tree.expandAll()


# Displays the filtered functions based on the selected plugin in Analysis box and POI box
def displayFilteredFunctions(view_tree, poi_list, filterContent, content, comment_text):
    funcTree = []
    for k in range(len(filterContent['function'])):
        for i in range(len(content)):
            if content[i]['name'] in filterContent['function'][k]['name']:
                parent = ''
                children = []
                if 'name' in content[i]:
                    parent = QTreeWidgetItem([content[i]['name']])
                if 'signature' in content[i]:
                    item = QTreeWidgetItem(parent, ["Signature: " + content[i]['signature']])
                    item.setToolTip(0, "Signature: " + content[i]['signature'])
                    children.append(item)
                if 'parameters' in content[i]:
                    params = []
                    paramData = []
                    for j in range(len(content[i]['parameters'])):
                        params.append(QTreeWidgetItem(children[len(children) - 1],
                                                      ["Arg " + str(j + 1) + ": " + content[i]['parameters'][j][
                                                          'name']]))
                        paramData.append(
                            QTreeWidgetItem(params[len(params) - 1], ["Type: " + content[i]['parameters'][j]['type']]))
                        paramData.append(
                            QTreeWidgetItem(params[len(params) - 1], ["Value: " + content[i]['parameters'][j]['value']]))
                    children.append(params)
                    children.append(paramData)
                if 'locals' in content[i]:
                    children.append(QTreeWidgetItem(parent, ["Local vars:"]))

                    local = []
                    localData = []
                    for j in range(len(content[i]['locals'])):
                        local.append(QTreeWidgetItem(children[len(children) - 1], [
                            "Local " + str(j + 1) + ": " + content[i]['locals'][j]['name']]))
                        localData.append(QTreeWidgetItem(local[len(local) - 1], ["Type: " + content[i]['locals'][j]['type']]))
                        localData.append(QTreeWidgetItem(local[len(local) - 1], ["Value: " + content[i]['locals'][j]['value']]))
                    children.append(local)
                    children.append(localData)
                if 'returnType' in content[i]:
                    children.append(QTreeWidgetItem(parent, ["Return Type: " + content[i]['returnType']]))
                if 'returnValue' in content[i]:
                    children.append(QTreeWidgetItem(parent, ["Return Value: " + content[i]['returnValue'] + "\n"]))

                item = QListWidgetItem(content[i]['name'])
                # set icon
                if getComment(content[i]['name'], "Function", comment_text):
                    addIcon(item)
                item.setCheckState(QtCore.Qt.Checked)
                poi_list.addItem(item)
                funcTree.append(parent)
    view_tree.addTopLevelItems(funcTree)
    view_tree.expandAll()


# Displays the strings extracted from Static Analysis in Analysis box and POI box
def displayString(view_tree, poi_list, content, comment_text):
    stringTree = []
    for i in range(len(content)):
        parent = ''
        children = []
        if 'name' in content[i]:
            parent = QTreeWidgetItem([content[i]['name']])
            parent.setToolTip(0, content[i]['name'])
            if 'type' in content[i]:
                children.append(QTreeWidgetItem(parent, ["Type: " + content[i]['type']]))
            if 'size' in content[i]:
                children.append(QTreeWidgetItem(parent, ["Size: " + str(content[i]['size'])]))
            if 'length' in content[i]:
                children.append(QTreeWidgetItem(parent, ["Length: " + str(content[i]['length'])]))
            if 'section' in content[i]:
                children.append(QTreeWidgetItem(parent, ["Section: " + content[i]['section'] + "\n"]))

        item = QListWidgetItem(content[i]['name'])
        # set icon
        if getComment(content[i]['name'], "String", comment_text):
            addIcon(item)
        poi_list.addItem(item)
        stringTree.append(parent)
    view_tree.addTopLevelItems(stringTree)
    view_tree.expandAll()


# Displays the filtered strings based on the selected plugin in Analysis box and POI box
def displayFilterStrings(view_tree, poi_list, filterContent, content, comment_text):
    stringTree = []
    for k in range(len(filterContent['string'])):
        for i in range(len(content)):
            if content[i]['name'] in filterContent['string'][k]['name']:
                parent = ''
                children = []
                if 'name' in content[i]:
                    parent = QTreeWidgetItem([content[i]['name']])
                    parent.setToolTip(0, content[i]['name'])
                    if 'type' in content[i]:
                        children.append(QTreeWidgetItem(parent, ["Type: " + content[i]['type']]))
                    if 'size' in content[i]:
                        children.append(QTreeWidgetItem(parent, ["Size: " + str(content[i]['size'])]))
                    if 'length' in content[i]:
                        children.append(QTreeWidgetItem(parent, ["Length: " + str(content[i]['length'])]))
                    if 'section' in content[i]:
                        children.append(QTreeWidgetItem(parent, ["Section: " + content[i]['section'] + "\n"]))

                item = QListWidgetItem(content[i]['name'])
                # set icon
                if getComment(content[i]['name'], "String", comment_text):
                    addIcon(item)
                poi_list.addItem(item)
                stringTree.append(parent)
    view_tree.addTopLevelItems(stringTree)
    view_tree.expandAll()


# Displays the variables extracted from Static Analysis in Analysis box and POI box
def displayVariable(view_tree, poi_list, content, comment_text):
    varTree = []
    for i in range(len(content)):
        parent = ''
        children = []
        if 'name' in content[i]:
            parent = QTreeWidgetItem([content[i]['name']])
        if 'type' in content[i]:
            children.append(QTreeWidgetItem(parent, ["Type: " + content[i]['type']]))
        if 'value' in content[i]:
            children.append(QTreeWidgetItem(parent, ["Value: " + content[i]['value'] + "\n"]))

        item = QListWidgetItem(content[i]['name'])
        # set icon
        if getComment(content[i]['name'], "Variable", comment_text):
            addIcon(item)
        varTree.append(parent)
        poi_list.addItem(item)
    view_tree.addTopLevelItems(varTree)
    view_tree.expandAll()


# Displays the filtered variables based on the selected plugin in Analysis box and POI box
def displayFilteredVariable(view_tree, poi_list, filterContent, content, comment_text):
    varTree = []
    for k in range(len(filterContent['variable'])):
        for i in range(len(content)):
            if content[i]['name'] in filterContent['variable'][k]['name']:
                parent = ''
                children = []
                if 'name' in content[i]:
                    parent = QTreeWidgetItem([content[i]['name']])
                if 'type' in content[i]:
                    children.append(QTreeWidgetItem(parent, ["Type: " + content[i]['type']]))
                if 'value' in content[i]:
                    children.append(QTreeWidgetItem(parent, ["Value: " + content[i]['value'] + "\n"]))

                item = QListWidgetItem(content[i]['name'])
                # set icon
                if getComment(content[i]['name'], "Variable", comment_text):
                    addIcon(item)
                varTree.append(parent)
                poi_list.addItem(item)
    view_tree.addTopLevelItems(varTree)
    view_tree.expandAll()


# Displays the dlls extracted from Static Analysis in Analysis box and POI box
def displayDll(view_tree, poi_list, content, comment_text):
    dllTree = []
    for i in range(len(content)):
        parent = ''
        if 'name' in content[i]:
            parent = QTreeWidgetItem([content[i]['name']])

        item = QListWidgetItem(content[i]['name'])
        # set icon
        if getComment(content[i]['name'], "DLL", comment_text):
            addIcon(item)
        poi_list.addItem(item)
        dllTree.append(parent)
    view_tree.addTopLevelItems(dllTree)
    view_tree.expandAll()


# Displays the filtered dlls based on the selected plugin in Analysis box and POI box
def displayFilteredDll(view_tree, poi_list, filterContent, content, comment_text):
    dllTree = []
    for k in range(len(filterContent['dll'])):
        for i in range(len(content)):
            if content[i]['name'] in filterContent['dll'][k]['name']:
                parent = ''
                if 'name' in content[i]:
                    parent = QTreeWidgetItem([content[i]['name']])

                item = QListWidgetItem(content[i]['name'])
                # set icon
                if getComment(content[i]['name'], "DLL", comment_text):
                    addIcon(item)
                poi_list.addItem(item)
                dllTree.append(parent)
    view_tree.addTopLevelItems(dllTree)
    view_tree.expandAll()
