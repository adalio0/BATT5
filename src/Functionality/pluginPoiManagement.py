from xmljson import parker as pk
import xml.etree.ElementTree as ET
import json
import xmlschema

def validatePluginXML(filepath):
    pluginSchema = xmlschema.XMLSchema('C:/Users/rivas/OneDrive/School/5 - Fall 2019/CS '
                                       '4311/BATT5/src/Configurations/pluginConfig.xsd')
    result = pluginSchema.is_valid(filepath)
    return result


def validatePoiXML(filepath):
    poiSchema = xmlschema.XMLSchema('C:/Users/rivas/OneDrive/School/5 - Fall 2019/CS '
                                    '4311/BATT5/src/Configurations/poiConfig.xsd')
    result = poiSchema.is_valid(filepath)
    return result


def convertPluginXML(filepath):
    if validatePluginXML(filepath):
        pluginTree = ET.parse(filepath)
        pluginRoot = pluginTree.getroot()
        pluginDict = json.loads(json.dumps(pk.data(pluginRoot)))
    else:
        print('invalid plugin XML (does not conform to  schema)')
    return pluginDict


def convertPoiXML(filepath):
    if validatePoiXML(filepath):
        poiTree = ET.parse(filepath)
        poiRoot = poiTree.getroot()
        poiDict = json.loads(json.dumps(pk.data(poiRoot)))
    else:
        print('invalid POI XML (does not conform to POI schema)')
    return poiDict


def convertPluginManual(name, desc, outName='', outFcnName='', outFcnSource=''):
    plugDict = {
        'name': name,
        'description': desc,
        'output': {
            'name': outName,
            'functionName': outFcnName,
            'functionSource': outFcnSource
        }
    }
    return plugDict


# SWITCH VIEWS
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

# TODO make function to store into db
