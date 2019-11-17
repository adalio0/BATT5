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
def convertFuncManual(name):
    funcDict = {
        'name': name
    }
    return funcDict

def convertStringManual(name):
    strDict = {
        'name': name
    }
    return strDict

def convertDllManual(name):
    dllDict = {
        'name': name
    }
    return dllDict

def convertVarManual(name):
    varDict = {
        'name': name
    }
    return varDict

def convertPacketProtocolManual(name):
    ppDict = {
        'name': name
    }
    return ppDict

def convertStructManual(name):
    structDict = {
        'name': name
    }
    return structDict

# ---------------- ADDING POIS TO PLUGINS ----------------
def addFuncToPlugin(pluginDict, funcDict):
    pluginDict['pointOfInterest']['function'].append(funcDict)
    print(pluginDict)
    return pluginDict

def addStringToPlugin(pluginDict, strDict):
    pluginDict['pointOfInterest']['string'].append(strDict)
    print(pluginDict)
    return pluginDict

def addVarToPlugin(pluginDict, varDict):
    pluginDict['pointOfInterest']['variable'].append(varDict)
    print(pluginDict)
    return pluginDict

def addDllToPlugin(pluginDict, dllDict):
    pluginDict['pointOfInterest']['dll'].append(dllDict)
    print(pluginDict)
    return pluginDict

def addPacketProtocolToPlugin(pluginDict, ppDict):
    pluginDict['pointOfInterest']['packetProtocol'].append(ppDict)
    print(pluginDict)
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

# ---------------- FORMAT XML ----------------

# ---------------- GUI ----------------

def processPOIDataFun(dpoimPlugin_dropdown, funcName_lineEdit):
    funDict = convertFuncManual(funcName_lineEdit.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addFuncToPlugin(finalPD, funDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())
    

def processPOIDataStr(dpoimPlugin_dropdown, strName_lineEdit):
    strDict = convertStringManual(strName_lineEdit.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addStringToPlugin(finalPD, strDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())

def processPOIDataVar(dpoimPlugin_dropdown, varName_lineEdit):
    varDict = convertVarManual(varName_lineEdit.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addVarToPlugin(finalPD, varDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())

def processPOIDataDLL(dpoimPlugin_dropdown, dllName_lineEdit):
    dllDict = convertDllManual(dllName_lineEdit.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addDllToPlugin(finalPD, dllDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())

def processPOIDataPP(dpoimPlugin_dropdown,protoName_lineEditself):
    ppDict = convertPacketProtocolManual(protoName_lineEditself.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addPacketProtocolToPlugin(finalPD, ppDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())

# ---------------- TESTING ----------------

