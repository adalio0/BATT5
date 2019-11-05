from xmljson import parker as pk
import xml.etree.ElementTree as ET
import json
import xmlschema
from pathlib import Path


def validatePluginXML(filepath):
    pluginSchema = xmlschema.XMLSchema('C:/Users/rivas/OneDrive/School/5 - Fall 2019/CS '
                                       '4311/BATT5/src/Configurations/pluginConfig.xsd')
    result = pluginSchema.is_valid(filepath)
    return result


def validatePoiXML(filepath):
    poiSchema = xmlschema.XMLSchema('C:/Users/rivas/OneDrive/School/5 - Fall 2019/CS '
                                    '4311/BATT5/src/Configurations/pluginConfig.xsd')
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

# TODO make function to store into db
