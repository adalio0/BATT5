from xmljson import BadgerFish
import xml.etree.ElementTree as ET

def validatePluginXML(filepath):
    return 1


def validatePoiXML(filepath):
    return 1


def convertPluginXML(filepath):
    if validatePluginXML(filepath):
        print('doing thing')
        pluginTree = ET.parse(filepath)
        pluginRoot = pluginTree.getroot()

    else:
        print('doing other thing (error)')
    return 1


def convertPoiXML(filepath, plugins):
    return 1


def convertPluginManual(name, desc, outFcnName='', outFcnSource=''):
    return 1
