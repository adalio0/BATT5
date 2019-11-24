from PyQt5.QtWidgets import QMessageBox
from xmljson import parker as pk
import xml.etree.ElementTree as ET
import json
import xmlschema
from pathlib import Path
from src.Functionality.database import *


# ---------------- XML VALIDATION ----------------
def validatePoiXML(filepath):
    poiSchema = xmlschema.XMLSchema(Path(__file__).parents[1].as_posix() + '/Configurations/poiConfig.xsd')
    result = poiSchema.is_valid(filepath)
    return result

# ---------------- XML CONVERSION ----------------
def convertPoiXML(ui, filepath):
    if validatePoiXML(filepath):
        poiTree = ET.parse(filepath)
        poiRoot = poiTree.getroot()
        poiDict = json.loads(json.dumps(pk.data(poiRoot)))
        return poiDict
    else:
        print('invalid POI XML (does not conform to POI schema)')
        QMessageBox.question(ui, "Error: Invalid File",
                             "Provided file must be an XML that conforms to poiConfig,xsd (schema)",
                             QMessageBox.Ok)
        return 0

# ---------------- MANUAL POI CONVERSION ----------------
def convertPoiManual(name):
    PoiDict = {
        'name': name
    }
    return PoiDict

# ---------------- ADDING POIS TO PLUGINS ----------------
def appendPoiPlugin(pluginDict, poiDict, poiType):
    poiType = poiType.lower()
    pluginDict['pointOfInterest'][poiType].append(poiDict)
    return pluginDict

def appendPoiPluginXml(pluginDict, poiDict):

    # for poiType in pluginDict['pointOfInterest']:  # for every poi type in plugin
    #     # print(poiType)
    #     for poi in poiDict[poiType]:  # for every poi of this type in poiDict
    #         # print('   ', poi)
    #         if poi not in pluginDict['pointOfInterest'][poiType]:  # if not already contained
    #             pluginDict['pointOfInterest'][poiType].append(poi)  # append poi

    for poi in poiDict['function']:
        if poi not in pluginDict['pointOfInterest']['function']:
            pluginDict['pointOfInterest']['function'].append(poi)

    for poi in poiDict['string']:
        if poi not in pluginDict['pointOfInterest']['string']:
            pluginDict['pointOfInterest']['string'].append(poi)

    for poi in poiDict['variable']:
        if poi not in pluginDict['pointOfInterest']['variable']:
            pluginDict['pointOfInterest']['variable'].append(poi)

    for poi in poiDict['dll']:
        if poi not in pluginDict['pointOfInterest']['dll']:
            pluginDict['pointOfInterest']['dll'].append(poi)

    for poi in poiDict['struct']:
        if poi not in pluginDict['pointOfInterest']['struct']:
            pluginDict['pointOfInterest']['struct'].append(poi)

    return pluginDict

# ---------------- ADDING POIS TO PLUGINS ----------------
def removePoiFromPlugin(pluginDict, poiName):
    for i in range(len(pluginDict['pointOfInterest']['function'])):
        if pluginDict['pointOfInterest']['function'][i]['name'] == poiName:
            pluginDict['pointOfInterest']['function'].pop(i)
            return pluginDict

    for i in range(len(pluginDict['pointOfInterest']['string'])):
        if pluginDict['pointOfInterest']['string'][i]['name'] == poiName:
            pluginDict['pointOfInterest']['string'].pop(i)
            return pluginDict

    for i in range(len(pluginDict['pointOfInterest']['variable'])):
        if pluginDict['pointOfInterest']['variable'][i]['name'] == poiName:
            pluginDict['pointOfInterest']['variable'].pop(i)
            return pluginDict

    for i in range(len(pluginDict['pointOfInterest']['dll'])):
        if pluginDict['pointOfInterest']['dll'][i]['name'] == poiName:
            pluginDict['pointOfInterest']['dll'].pop(i)
            return pluginDict

    for i in range(len(pluginDict['pointOfInterest']['struct'])):
        if pluginDict['pointOfInterest']['struct'][i]['name'] == poiName:
            pluginDict['pointOfInterest']['struct'].pop(i)
            return pluginDict


# ---------------- FORMAT XML ----------------
def formatPoi(poiDict):
    newPoiDict = {
        'function': [],
        'string': [],
        'variable': [],
        'dll': [],
        'struct': [],
        'packetProtocol': []
    }
    poiTypes = ['function', 'string', 'variable', 'dll', 'packetProtocol', 'struct']
    for t in poiTypes:
        if t in poiDict:
            if len(poiDict[t]) == 1:
                newPoiDict[t] = [poiDict[t]]
            elif len(poiDict[t]) > 1:
                newPoiDict[t] = poiDict[t]

    return newPoiDict

# ---------------- GUI ----------------
def addPoiToPlugin(ui, poiName, poiType, pluginName):
    if poiName == '':
        QMessageBox.question(ui, "Error: Empty Field",
                             "The required field cannot be empty",
                             QMessageBox.Ok)
        return 0
    poiDict = convertPoiManual(poiName)
    updatedPluginDict = appendPoiPlugin(getCurrentPluginInfo(pluginName), poiDict, poiType)
    updatePlugin(updatedPluginDict, pluginName)

def addPoiToPluginXml(ui, filepath, pluginName):
    if filepath == '':
        QMessageBox.question(ui, "Error: Empty Field",
                             "The required field cannot be empty",
                             QMessageBox.Ok)
        return 0
    poiDict = convertPoiXML(ui, filepath)
    if poiDict == 0:
        return 0
    formatedPoiDict = formatPoi(poiDict)
    pluginDict = getCurrentPluginInfo(pluginName)
    updatedPluginDict = appendPoiPluginXml(pluginDict, formatedPoiDict)
    updatePlugin(updatedPluginDict, pluginName)
# ---------------- TESTING ----------------
