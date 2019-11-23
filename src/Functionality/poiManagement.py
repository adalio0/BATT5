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
def convertPoiXML(filepath):
    if validatePoiXML(filepath):
        poiTree = ET.parse(filepath)
        poiRoot = poiTree.getroot()
        poiDict = json.loads(json.dumps(pk.data(poiRoot)))
        return poiDict
    else:
        print('invalid POI XML (does not conform to POI schema)')
        # TODO display error window
        return

# ---------------- MANUAL POI CONVERSION ----------------
def convertPoiManual(name):
    PoiDict = {
        'name': name
    }
    return PoiDict

# ---------------- ADDING POIS TO PLUGINS ----------------
def appendPoiPlugin(pluginDict, poiDict, poiType):
    pluginDict['pointOfInterest'][poiType].append(poiDict)
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

# ---------------- GUI ----------------
def addPoiToPlugin(poiName, poiType, pluginName):
    poiDict = convertPoiManual(poiName)
    pluginDict = getCurrentPluginInfo(pluginName)

    updatedPlugin = appendPoiPlugin(pluginDict, poiDict, poiType.lower())
    updatePlugin(updatedPlugin, pluginName)

# ---------------- TESTING ----------------

