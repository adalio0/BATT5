from src.Functionality.Management.poiManagement import *

# ---------------- XML VALIDATION ----------------
def validatePluginXML(filepath):
    try:
        pluginSchema = xmlschema.XMLSchema(Path(__file__).parents[3].as_posix() + '/Configurations/pluginConfig.xsd')
        return pluginSchema.is_valid(filepath)
    except:
        return 0

# ---------------- XML CONVERSION ----------------
def convertPluginXML(filepath):
    if validatePluginXML(filepath):
        pluginTree = ET.parse(filepath)
        pluginRoot = pluginTree.getroot()
        pluginDict = json.loads(json.dumps(pk.data(pluginRoot)))
        pluginDict = formatPluginXml(pluginDict)
        return pluginDict
    else:
        return 0

# ---------------- MANUAL PLUGIN CONVERSION ----------------
def convertPluginManual(name, desc):
    plugDict = {
        'name': name,
        'description': desc,
        'pointOfInterest': {
            'function': [],
            'string': [],
            'variable': [],
            'dll': [],
            'packetProtocol': [],
            'struct': []
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
            'struct': [],
            'packetProtocol': []
        }
    }

    if 'pointOfInterest' in pluginDict:
        poiTypes = ['function', 'string', 'variable', 'dll', 'packetProtocol', 'struct']
        for t in poiTypes:
            if t in pluginDict['pointOfInterest']:
                if len(pluginDict['pointOfInterest'][t]) == 1:
                    newPluginDict['pointOfInterest'][t] = [pluginDict['pointOfInterest'][t]]
                elif len(pluginDict['pointOfInterest'][t]) > 1:
                    newPluginDict['pointOfInterest'][t] = pluginDict['pointOfInterest'][t]

    return newPluginDict

# ---------------- GUI ----------------
def savePluginXML(ui, dpmPluginStructure_lineEdit):
    pluginDict = convertPluginXML(dpmPluginStructure_lineEdit.text())
    if pluginDict == 0:
        QMessageBox.question(ui, "Error: Invalid File",
                             "Provided file must be an XML that conforms to pluginConfig,xsd (schema)",
                             QMessageBox.Ok)
        return 0

    savePlugin(pluginDict)

def savePluginManual(ui, dpmPluginName_lineEdit, dpmPluginDesc_lineEdit):
    if dpmPluginName_lineEdit.text() == '' or dpmPluginDesc_lineEdit.text() == '':
        QMessageBox.question(ui, "Error: Empty Fields",
                             "All fields must be filled to in order to create or update a plugin",
                             QMessageBox.Ok)
        return 0
    else:
        pluginDict = convertPluginManual(dpmPluginName_lineEdit.text(), dpmPluginDesc_lineEdit.text(),)
        savePlugin(pluginDict)

# ---------------- Plugin Modification ----------------
def modifyPlugin(ui, oldName, newName, newDesc):
    if newName == '' or newDesc == '':
        QMessageBox.question(ui, "Error: Empty Fields",
                             "All fields must be filled to in order to create or update a plugin",
                             QMessageBox.Ok)
        return
    pluginDict = getCurrentPluginInfo(oldName)
    pluginDict['name'] = newName
    pluginDict['description'] = newDesc
    updatePlugin(pluginDict, oldName)

# ---------------- DATABASE ----------------
def saveToDatabase(plugin):
    savePlugin(plugin)

# ---------------- TEST ----------------
