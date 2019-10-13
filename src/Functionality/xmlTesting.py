import os
import xml.etree.ElementTree as ET


def xmlParser():
    cur_path = os.getcwd()
    file = os.path.join(cur_path, '..', 'Configurations', 'project1.xml')
    tree = ET.parse(file)
    root = tree.getroot()

    text = "<b>Project Description</b>: This is a description of the project that is currently selected. \n"
    text += "<b>Project Properties:</b> \n"

    for child in root.iter():
        if child.get('name') is not None:
            text += "<b>" + child.tag + "</b>" + ": " + child.get('name') + "\n"

    print(text)

    tree.write(file)


if __name__ == "__main__":
    xmlParser()
