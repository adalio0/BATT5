from xmljson import parker as pk
import xml.etree.ElementTree as ET
import json
import xmlschema
from pathlib import Path

# ---------------- XML VALIDATION ----------------
def validatePluginXML(filepath):
    pluginSchema = xmlschema.XMLSchema(Path(__file__).parents[1].as_posix() + '/Configurations/pluginConfig.xsd')
    result = pluginSchema.is_valid(filepath)
    return result

def validatePoiXML(filepath):
    poiSchema = xmlschema.XMLSchema(Path(__file__).parents[1].as_posix() + '/Configurations/poiConfig.xsd')
    result = poiSchema.is_valid(filepath)
    return result

# ---------------- XML CONVERSION ----------------
def convertPluginXML(filepath):
    if validatePluginXML(filepath):
        pluginTree = ET.parse(filepath)
        pluginRoot = pluginTree.getroot()
        pluginDict = json.loads(json.dumps(pk.data(pluginRoot)))
        return pluginDict
    else:
        print('invalid plugin XML (does not conform to  schema)')
        # TODO display error window
        return

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

# ---------------- MANUAL PLUGIN CONVERSION ----------------
def convertPluginManual(name, desc, outName='', outFcnName='', outFcnSource=''):
    plugDict = {
        'name': name,
        'description': desc,
        'pointOfInterest': {
            'function': None,
            'string': None,
            'variable': None,
            'dll': None,
            'packetProtocol': None
        },
        'output': {
            'name': outName,
            'functionName': outFcnName,
            'functionSource': outFcnSource
        }
    }
    return plugDict

# ---------------- MANUAL POI CONVERSION ----------------
def convertFuncManual():
    # TODO
    return 0

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
    pluginList[2][1]['function'].append(funcDict)  # append new poi
    pluginDict['pointOfInterest']['function'] = pluginList[2][1]['function']  # add to dict
    return pluginDict

def addStringToPlugin(pluginDict, strDict):
    pluginList = [[k, v] for k, v in pluginDict.items()]  # convert dict to list for appending
    pluginList[2][1]['string'].append(strDict)  # append new poi
    pluginDict['pointOfInterest']['string'] = pluginList[2][1]['string']  # add to dict
    return pluginDict

def addVarToPlugin(pluginDict, varDict):
    pluginList = [[k, v] for k, v in pluginDict.items()]  # convert dict to list for appending
    pluginList[2][1]['variable'].append(varDict)  # append new poi
    pluginDict['pointOfInterest']['variable'] = pluginList[2][1]['variable']  # add to dict
    return pluginDict

def addDllToPlugin(pluginDict, dllDict):
    pluginList = [[k, v] for k, v in pluginDict.items()]  # convert dict to list for appending
    pluginList[2][1]['dll'].append(dllDict)  # append new poi
    pluginDict['pointOfInterest']['dll'] = pluginList[2][1]['dll']  # add to dict
    return pluginDict

def addPacketProtocolToPlugin(pluginDict, ppDict):
    pluginList = [[k, v] for k, v in pluginDict.items()]  # convert dict to list for appending
    pluginList[2][1]['packetProtocol'].append(ppDict)  # append new poi
    pluginDict['pointOfInterest']['packetProtocol'] = pluginList[2][1]['packetProtocol']  # add to dict
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

def switchPluginCreateView(createType, createPlugin_stack):
    if createType == 'Pull From XML File':
        createPlugin_stack.setCurrentIndex(0)
    if createType == 'Manual Input':
        createPlugin_stack.setCurrentIndex(1)

def processPluginData(createType, dpmPluginStructure_lineEdit, dpmPluginName_lineEdit, dpmPluginDesc_lineEdit,
                      dpmOutName_lineEdit, dpmOutFuncName_lineEdit, dpmOutFuncSource_lineEdit):
    if createType == 'Pull From XML File':
        pluginDict = convertPluginXML(dpmPluginStructure_lineEdit.text())

    elif createType == 'Manual Input':
        pluginDict = convertPluginManual(dpmPluginName_lineEdit.text(), dpmPluginDesc_lineEdit.text(),
                                         dpmOutName_lineEdit.text(), dpmOutFuncName_lineEdit.text(),
                                         dpmOutFuncSource_lineEdit.text())
    print(pluginDict)
    return pluginDict

# TODO make function to store into db

'''
# ---------------- TESTING ----------------
# create network plugin dict
'''
