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


# ---------------- MANUAL PLUGIN CONVERSION ----------------
def convertPluginManual(name, desc, outName='', outFcnName='', outFcnSource=''):
    plugDict = {
        'name': name,
        'description': desc,
        'pointOfInterest': {
            'function': '',
            'string': '',
            'variable': '',
            'dll': '',
            'packetProtocol': ''
        },
        'output': {
            'name': outName,
            'functionName': outFcnName,
            'functionSource': outFcnSource
        }
    }
    return plugDict

# ---------------- FORMAT XML ----------------
def formatPluginXml():
    return 0

# ---------------- GUI ----------------

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
