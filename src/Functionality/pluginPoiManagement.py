from xmljson import parker as pk
import xml.etree.ElementTree as ET
import json
import xmlschema
from pathlib import Path
# from dicttoxml import dicttoxml

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

def convertPacketProtocolManual():
    # TODO
    return 0

# ---------------- ADDING POIS TO PLUGINS ----------------

def addStringToPlugin(pluginDict, poiDict):
    return 0

def addFuncToPlugin(pluginDict, poiDict):
    return 0

def addVarToPlugin(pluginDict, poiDict):
    return 0

def addDllToPlugin(pluginDict, poiDict):
    return 0

def addPacketProtocolToPlugin(pluginDict, poiDict):
    return 0

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
testPlugin = convertPluginXML('C:/Users/rivas/OneDrive/School/5 - '
                              'Fall 2019/CS 4311/BATT5/src/Configurations/networkPlugin.xml')
print(testPlugin, '\n')

# create str to add to plugin
testStr = convertStringManual(name='yuh', size=2)
print(testStr, '\n')

# convert netPlugin to list
testList = [[k, v] for k, v in testPlugin.items()]
print(testList, '\n')

# append new poi to list
testList[2][1]['string'].append(testStr)
print(testList[2][1]['string'][2], '\n')  # new poi added!

# modify dict to include new str
testPlugin['pointOfInterest']['string'] = testList[2][1]['string']
print(testPlugin['pointOfInterest'])
print(testPlugin['pointOfInterest']['string'])
print(testList[2][1]['function'])
'''