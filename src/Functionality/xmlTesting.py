import os
import xml.etree.ElementTree as ET

from pathlib import Path


def xmlParser():
    cur_path = os.getcwd()
    file = os.path.join(cur_path, '..', 'Configurations', 'country_data.xml')
    tree = ET.parse(file)
    root = tree.getroot()

    print(root.tag)
    for child in root:
        print(child.tag, child.attrib)

    print(root[0][0].text)

    for rank in root.iter('rank'):
        new_rank = int(rank.text) + 1
        rank.text = str(new_rank)
        rank.set('updated', 'yes')

    tree.write(file)


if __name__ == "__main__":
    xmlParser()
