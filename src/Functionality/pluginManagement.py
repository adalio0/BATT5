from src.Functionality.poiManagement import *

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
        pluginDict = formatPluginXml(pluginDict)
        return pluginDict
    else:
        print('invalid plugin XML (does not conform to  schema)')
        # TODO display error window
        return

# ---------------- MANUAL PLUGIN CONVERSION ----------------
def convertPluginManual(name, desc, outName='', outFcnName='', outFcnSource=''):
    plugDict = {
        '_id': '',
        'name': name,
        'description': desc,
        'pointOfInterest': {
            'function': [],
            'string': [],
            'variable': [],
            'dll': [],
            'packetProtocol': []
        },
        'output': {
            'name': outName,
            'functionName': outFcnName,
            'functionSource': outFcnSource
        }
    }
    return plugDict

# ---------------- FORMAT XML ----------------
def formatPluginXml(pluginDict):
    newPluginDict = {
        'name': pluginDict['name'],
        'description': pluginDict['description'],
        'pointOfInterest': {
            'function': [],
            'string': [],
            'variable': [],
            'dll': [],
            'packetProtocol': []
        },
        'output': {
            'name': '',
            'functionName': '',
            'functionSource': ''
        }
    }

    if 'pointOfInterest' in pluginDict:

        if 'function' in pluginDict['pointOfInterest']:
            if len(pluginDict['pointOfInterest']['function']) == 1:
                newPluginDict['pointOfInterest']['function'] = [pluginDict['pointOfInterest']['function']]
            elif len(pluginDict['pointOfInterest']['function']) > 1:
                newPluginDict['pointOfInterest']['function'] = pluginDict['pointOfInterest']['function']

        if 'string' in pluginDict['pointOfInterest']:
            if len(pluginDict['pointOfInterest']['string']) == 1:
                newPluginDict['pointOfInterest']['string'] = [pluginDict['pointOfInterest']['string']]
            elif len(pluginDict['pointOfInterest']['string']) > 1:
                newPluginDict['pointOfInterest']['string'] = pluginDict['pointOfInterest']['string']

        if 'variable' in pluginDict['pointOfInterest']:
            if len(pluginDict['pointOfInterest']['variable']) == 1:
                newPluginDict['pointOfInterest']['variable'] = [pluginDict['pointOfInterest']['variable']]
            elif len(pluginDict['pointOfInterest']['variable']) > 1:
                newPluginDict['pointOfInterest']['variable'] = pluginDict['pointOfInterest']['variable']

        if 'dll' in pluginDict['pointOfInterest']:
            if len(pluginDict['pointOfInterest']['dll']) == 1:
                newPluginDict['pointOfInterest']['dll'] = [pluginDict['pointOfInterest']['dll']]
            elif len(pluginDict['pointOfInterest']['dll']) > 1:
                newPluginDict['pointOfInterest']['dll'] = pluginDict['pointOfInterest']['dll']

        if 'packetProtocol' in pluginDict['pointOfInterest']:
            if len(pluginDict['pointOfInterest']['packetProtocol']) == 1:
                newPluginDict['pointOfInterest']['packetProtocol'] = [pluginDict['pointOfInterest']['packetProtocol']]
            elif len(pluginDict['pointOfInterest']['packetProtocol']) > 1:
                newPluginDict['pointOfInterest']['packetProtocol'] = pluginDict['pointOfInterest']['packetProtocol']

    if 'output' in pluginDict:
        if 'name' in pluginDict['output']:
            newPluginDict['output']['name'] = pluginDict['output']['name']

        if 'functionName' in pluginDict['output']:
            newPluginDict['output']['functionName'] = pluginDict['output']['functionName']

        if 'functionSource' in pluginDict['output']:
            newPluginDict['output']['functionSource'] = pluginDict['output']['functionSource']

    return newPluginDict

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
    # save plugin to database
    savePlugin(pluginDict)
    return pluginDict

# ---------------- DATABASE ----------------
def saveToDatabase(plugin):
    savePlugin(plugin)

# ---------------- TEST ----------------
# testPlugin = convertPluginXML('C:/Users/rivas/OneDrive/School/5 - Fall 2019/CS 4311/BATT5/src/Configurations/networkPlugin.xml')
# print(testPlugin)
# testPlugin = removePoiFromPlugin(testPlugin, 'Sleep')
# print(testPlugin)
