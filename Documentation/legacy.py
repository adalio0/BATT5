import os
import sys
import glob
import xml.etree.ElementTree as ET
from pathlib import Path

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

    # try:
    #     staticAnalysis(path)
    # except:
    #     print("Radare2 not installed cannot start static analysis.")

    self.displayPoi()