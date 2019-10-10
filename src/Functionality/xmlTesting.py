import os
import xml.etree.ElementTree as ET


def xmlParser():
    cur_path = os.getcwd()
    file = os.path.join(cur_path, '..', 'Configurations', 'project.xml')
    tree = ET.parse(file)
    root = tree.getroot()

    print(root.tag)
    for child in root:
        print(child.tag, child.attrib, child[0].text)

    for element in root.iter('os'):
        element.set('content', 'Linux')

    value = root.find('.//project/os[@name="{}"]'.format('Linux')).text
    print(value)

    tree.write(file)


if __name__ == "__main__":
    xmlParser()
