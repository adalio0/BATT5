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

def convertStringManual(name, type='', size='', callFromAdd='', destAdd='', section=''):
    strDict = {
        'name': name,
        'type': type,
        'size': size,
        'callFromAddress': callFromAdd,
        'destinationAddress': destAdd,
        'section': section
    }
    return strDict

def convertDllManual(name):
    dllDict = {
        'name': name
    }
    return dllDict

def convertVarManual(name, type='', val='', size=''):
    varDict = {
        'name': name,
        'type': type,
        'value': val,
        'size': size
    }
    return varDict

def convertPacketProtocolManual(name, fieldName='', fieldType=''):
    ppDict = {
        'name': name,
        'fieldName': fieldName,
        'fieldType': fieldType
    }
    return ppDict


def convertStructManual():
    # TODO
    return 0

# ---------------- ADDING POIS TO PLUGINS ----------------

def addFuncToPlugin(pluginDict, funcDict):
    pluginList = [[k, v] for k, v in pluginDict.items()]  # convert dict to list for appending
    pluginList[3][1]['function'].append(funcDict)  # append new poi
    pluginDict['pointOfInterest']['function'] = pluginList[3][1]['function']  # add to dict
    return pluginDict

def addStringToPlugin(pluginDict, strDict):
    pluginList = [[k, v] for k, v in pluginDict.items()]  # convert dict to list for appending
    pluginList[3][1]['string'].append(strDict)  # append new poi
    pluginDict['pointOfInterest']['string'] = pluginList[3][1]['string']  # add to dict
    return pluginDict

def addVarToPlugin(pluginDict, varDict):
    pluginList = [[k, v] for k, v in pluginDict.items()]  # convert dict to list for appending
    pluginList[3][1]['variable'].append(varDict)  # append new poi
    pluginDict['pointOfInterest']['variable'] = pluginList[3][1]['variable']  # add to dict
    print(pluginDict)
    return pluginDict

def addDllToPlugin(pluginDict, dllDict):
    pluginList = [[k, v] for k, v in pluginDict.items()]  # convert dict to list for appending
    pluginList[3][1]['dll'].append(dllDict)  # append new poi
    pluginDict['pointOfInterest']['dll'] = pluginList[3][1]['dll']  # add to dict
    return pluginDict

def addPacketProtocolToPlugin(pluginDict, ppDict):
    pluginList = [[k, v] for k, v in pluginDict.items()]  # convert dict to list for appending
    pluginList[3][1]['packetProtocol'].append(ppDict)  # append new poi
    pluginDict['pointOfInterest']['packetProtocol'] = pluginList[3][1]['packetProtocol']  # add to dict
    return pluginDict

# ---------------- FORMAT XML ----------------

# ---------------- GUI ----------------
def switchPOITypeView(poiType, addPOI_stack):
    if poiType == 'Pull From Predefined Dataset':
        addPOI_stack.setCurrentIndex(0)
    elif poiType == 'Function':
        addPOI_stack.setCurrentIndex(1)
    elif poiType == 'String':
        addPOI_stack.setCurrentIndex(2)
    elif poiType == 'Variable':
        addPOI_stack.setCurrentIndex(3)
    elif poiType == 'DLL':
        addPOI_stack.setCurrentIndex(4)
    elif poiType == 'Packet Protocol':
        addPOI_stack.setCurrentIndex(5)
    elif poiType == 'Struct':
        addPOI_stack.setCurrentIndex(6)

def processPOIDataFun(dpoimPlugin_dropdown,funcName_lineEdit,funcRetType_lineEdit,funcRetCal_lineEdit,
    funcCallFrom_lineEdit,funcDestAddress_lineEdit,funcNumParam_lineEdit):
    funDict = convertFuncManual(funcName_lineEdit.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addFuncToPlugin(finalPD, funDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())
    

def processPOIDataStr(dpoimPlugin_dropdown,strName_lineEdit,strType_lineEdit,strSize_lineEdit, 
                strCallFrom_lineEdit,strDest_lineEdit,trSection_linEdit):
    strDict = convertStringManual(strName_lineEdit.text(),strType_lineEdit.text(),strSize_lineEdit.text(), 
                strCallFrom_lineEdit.text(),strDest_lineEdit.text(),trSection_linEdit.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addStringToPlugin(finalPD, strDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())

def processPOIDataVar(dpoimPlugin_dropdown,varName_lineEdit,varType_lineEdit,varValue_lineEdit,varSize_lineEdit):
    varDict = convertVarManual(varName_lineEdit.text(),varType_lineEdit.text(),varValue_lineEdit.text(),varSize_lineEdit.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addVarToPlugin(finalPD, varDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())

def processPOIDataDLL(dpoimPlugin_dropdown,dllName_lineEdit):
    dllDict = convertDllManual(dllName_lineEdit.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addDllToPlugin(finalPD, dllDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())

def processPOIDataPP(dpoimPlugin_dropdown,protoName_lineEditself,
                protoFieldName_lineEdit,protoFieldType_lineEdit):
    ppDict = convertPacketProtocolManual(protoName_lineEditself.text(),protoFieldName_lineEdit.text(),protoFieldType_lineEdit.text())
    finalPD = getCurrentPluginInfo(dpoimPlugin_dropdown.currentText())
    pluginDictNew = addPacketProtocolToPlugin(finalPD, ppDict)
    updatePlugin(pluginDictNew, dpoimPlugin_dropdown.currentText())

#def processPOIDataS(self.window.dpoimPlugin_dropdown,self.window.StructTBD_text):

