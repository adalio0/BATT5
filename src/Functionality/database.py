import pymongo
import base64

# Initializes the connection with our local database
client = pymongo.MongoClient("mongodb://localhost:27017")
db = client['project_data']
project_db = db['project']
binary_db = db['binary']
static_db = db['static']
results_db = db['results']
function_db = db['function']
string_db = db['string']
variable_db = db['variable']
dll_db = db['dll']
# packet_protocols_db = db['packet_protocols']
struct_db = db['struct']
db_1 = client['current_project']
current_db = db_1['current']

db_2 = client['plugin_data']
plugin_db = db_2['plugins']


# Checks if static analysis has been performed on the current selected project
def checkStatic():
    flag = False
    for c in current_db.find():
        for p in project_db.find():
            if p['_id'] == c.get('id'):
                flag = p.get('static_analysis', {}).get('performed')
    return flag


# ---- Setters for the database (sets the current project and window title) --------------------------------------

def setWindowTitle():
    for c in current_db.find():
        for p in project_db.find():
            if p['_id'] == c.get('id'):
                return p['name']
    return "BATT5"


# Gets all the information of the current project from the database and sets it into the database
def setCurrentProject(selected):
    if selected:
        db_1.current.drop()
        item = selected[0].text(0)
        for p in project_db.find():
            if p['name'] == item:
                project_data = {
                    'id': p['_id']
                }
                current_outcome = current_db.insert_one(project_data)

    text = ""
    binaryPath = ""
    for c in current_db.find():
        for p in project_db.find():
            if p['_id'] == c.get('id'):
                for b in binary_db.find():
                    if b['_id'] == p.get('binary'):
                        text = "<font size=3> <b>Project Description</b>: " + p.get('description') + "<br><br>"
                        text += "<b>Binary Properties</b>: <br>"
                        text += "<b>" + "File" + "</b>: " + b.get('file') + "<br>"
                        text += "<b>" + "Os" + "</b>: " + b.get('os') + "<br>"
                        text += "<b>" + "Binary" + "</b>: " + b.get('binary') + "<br>"
                        text += "<b>" + "Machine" + "</b>: " + b.get('machine') + "<br>"
                        text += "<b>" + "Class" + "</b>: " + b.get('class') + "<br>"
                        text += "<b>" + "Bits" + "</b>: " + b.get('bits') + "<br>"
                        text += "<b>" + "Language" + "</b>: " + b.get('language') + "<br>"
                        text += "<b>" + "Canary" + "</b>: " + b.get('canary') + "<br>"
                        text += "<b>" + "Crypto" + "</b>: " + b.get('crypto') + "<br>"
                        text += "<b>" + "Nx" + "</b>: " + b.get('nx') + "<br>"
                        text += "<b>" + "Pic" + "</b>: " + b.get('pic') + "<br>"
                        text += "<b>" + "Relocs" + "</b>: " + b.get('relocs') + "<br>"
                        text += "<b>" + "Relro" + "</b>: " + b.get('relro') + "<br>"
                        text += "<b>" + "Stripped" + "</b>: " + b.get('stripped') + "<br> </font>"
                        binaryPath = b.get('file')

    return text, binaryPath


# ---- Getters for the database (Gets appropriate data based on request) --------------------------------------

# Gets all of the projects that were created from the database
def getProjects():
    # deleteDatabase()
    projects = []
    for p in project_db.find():
        projects.append(p.get('name'))
    return projects


# Gets the path of the current project's file
def getCurrentFilePath():
    for c in current_db.find():
        for p in project_db.find():
            if p['_id'] == c.get('id'):
                for b in binary_db.find():
                    if b['_id'] == p.get('binary'):
                        return b.get('file')


# Gets all the current plugins for the project
def getPlugins():
    # deletePluginDatabase()
    plugins = []
    for p in plugin_db.find():
        plugins.append(p.get('name'))
    return plugins


# Get the currently selected plugin's info
def getCurrentPlugin(selected):
    name = ''
    description = ''
    pointOfInterest = ''
    output = ''
    if selected:
        for p in plugin_db.find():
            if p['name'] == selected:
                name = p['name']
                description = p['description']
                pointOfInterest = p['pointOfInterest']
                output = p['output']
    return name, description, pointOfInterest, output


# Get the currently selected plugin
def getCurrentPluginInfo(selected):
    if selected:
        for p in plugin_db.find():
            if p['name'] == selected:
                return p

# Gets the appropriate database
def getAppropriatePoi(poi):
    if poi == "Function":
        return function_db
    elif poi == "String":
        return string_db
    elif poi == "Variable":
        return variable_db
    elif poi == "DLL":
        return dll_db
    elif poi == "Struct":
        return struct_db

# Displays specific POI in the Analysis box
def getPoi(poi):
    entries = []
    for c in current_db.find():
        for p in project_db.find():
            if p['_id'] == c.get('id'):
                for s in static_db.find():
                    if s['_id'] == p.get('static_analysis', {}).get('01'):
                        for r in results_db.find():
                            if r['_id'] == s.get('results').get('01'):
                                database = getAppropriatePoi(poi)
                                for d in database.find():
                                    if r['_id'] == d.get('results_id'):
                                        content = d.get('data')
                                        try:
                                            entries.append(content)
                                        except TypeError:
                                            pass
    return entries


# Gets the pois from given plugin that will be used in filtering out a specified poi type
def getFilterPoi(plugin):
    for p in plugin_db.find():
        if p['name'] == plugin:
            return p.get('pointOfInterest', {})


# Gets the pois that have been defined in a given plugin
def getPoisFromPlugin(plugin):
    pois = []
    for p in plugin_db.find():
        if plugin == p.get('name'):
            for i in range(len(p['pointOfInterest']['function'])):
                pois.append(p['pointOfInterest']['function'][i]['name'])

            for i in range(len(p['pointOfInterest']['string'])):
                pois.append(p['pointOfInterest']['string'][i]['name'])

            for i in range(len(p['pointOfInterest']['variable'])):
                pois.append(p['pointOfInterest']['variable'][i]['name'])

            for i in range(len(p['pointOfInterest']['dll'])):
                pois.append(p['pointOfInterest']['dll'][i]['name'])
    return pois


# Gets the comment associated with the given poi
def getComment(poiName, dropText, commentBox):
    database = getAppropriatePoi(dropText)
    for d in database.find():
        if poiName == d.get('name'):
            commentBox.setText(d.get('comment'))
            if d.get('comment'):
                return 1


# ---- Methods that save/insert data into the database -----------------------------------------------

# Saves a created plugin into the database
def savePlugin(plugin):
    plugin_db.insert_one(plugin)


# Updates a given plugin if a new poi was defined
def updatePlugin(plugin, name):
    plugin_db.find_one_and_delete(
        {'name': name}
    )
    plugin_db.insert_one(plugin)


# Saves a comment to a specific poi
def saveComment(comment, poiName, dropText):
    database = getAppropriatePoi(dropText)
    database.find_one_and_update(
        {'name': poiName},
        {'$set': {'comment': comment}},
        upsert=False)


# Gets and saves Static Analysis results into database
def saveStatic(poi):
    for c in current_db.find():
        for p in project_db.find():
            if p['_id'] == c.get('id'):
                for s in static_db.find():
                    if s['_id'] == p.get('static_analysis', {}).get('01'):
                        project_db.find_one_and_update(
                            {'_id': c['id']},
                            {'$set': {'static_analysis': {'performed': True, '01': s['_id']}}}, upsert=True)
                        for r in results_db.find():
                            if r['_id'] == s.get('results').get('01'):
                                # SAVE FUNCTIONS and CREATE PARAMETERS LIST FOR FUNCTIONS
                                for i in range(len(poi[0])):
                                    parameters = []
                                    try:
                                        for j in range(len(poi[0][i]['regvars'])):
                                            info = {
                                                'name': poi[0][i]['regvars'][j]['name'],
                                                'type': poi[0][i]['regvars'][j]['type'],
                                                'value': ''
                                            }
                                            parameters.append(info)
                                    except KeyError:
                                        continue

                                    try:
                                        for j in range(len(poi[0][i]['spvars'])):
                                            if j >= poi[0][i]['nlocals']:
                                                info = {
                                                    'name': poi[0][i]['spvars'][j]['name'],
                                                    'type': poi[0][i]['spvars'][j]['type'],
                                                    'value': ''
                                                }
                                                parameters.append(info)
                                    except KeyError:
                                        continue

                                    function = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'name': poi[0][i]['name'],
                                        'data': {
                                            'name': poi[0][i]['name'],
                                            'signature': poi[0][i]['signature'],
                                            'parameters': parameters,
                                            'returnType': '',
                                            'returnValue': ''
                                        }
                                    }
                                    function_outcome = function_db.insert_one(function)

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'function': {str(i): function['_id']}}}, upsert=True)

                                # SAVE STRINGS
                                for i in range(len(poi[1])):
                                    string = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'name': poi[1][i]['string'],
                                        'data': {
                                            'name': poi[1][i]['string'],
                                            'type': poi[1][i]['type'],
                                            'size': poi[1][i]['size'],
                                            'length': poi[1][i]['length'],
                                            'section': poi[1][i]['section']
                                        }
                                    }
                                    string_outcome = string_db.insert_one(string)

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'string': {str(i): string['_id']}}}, upsert=True)

                                # SAVE SP VARIABLES
                                for i in range(len(poi[2]['sp'])):
                                    variable = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'name': poi[2]['sp'][i]['name'],
                                        'data': {
                                            'name': poi[2]['sp'][i]['name'],
                                            'type': poi[2]['sp'][i]['type'],
                                            'size': poi[2]['sp'][i]['ref']['offset'],
                                            'value': ''
                                        }
                                    }
                                    variable_outcome = variable_db.insert_one(variable)

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'variable': {str(i): variable['_id']}}}, upsert=True)

                                # SAVE BP VARIABLES
                                for i in range(len(poi[2]['bp'])):
                                    variable = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'name': poi[2]['bp'][i]['name'],
                                        'data': {
                                            'name': poi[2]['bp'][i]['name'],
                                            'type': poi[2]['bp'][i]['type'],
                                            'size': poi[2]['bp'][i]['ref']['offset'],
                                            'value': ''
                                        }
                                    }
                                    variable_outcome = variable_db.insert_one(variable)
                                    # print(variable)

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'variable': {str(i): variable['_id']}}}, upsert=True)

                                # SAVE REG VARIABLES
                                for i in range(len(poi[2]['reg'])):
                                    variable = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'name': poi[2]['reg'][i]['name'],
                                        'data': {
                                            'name': poi[2]['reg'][i]['name'],
                                            'type': poi[2]['reg'][i]['type'],
                                            'value': ''
                                        }
                                    }
                                    variable_outcome = variable_db.insert_one(variable)

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'variable': {str(i): variable['_id']}}}, upsert=True)

                                # SAVE DLLs
                                for i in range(len(poi[3])):
                                    dll = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'name': poi[3][i]['name'],
                                        'data': {
                                            'name': poi[3][i]['name']
                                        }
                                    }
                                    dll_outcome = dll_db.insert_one(dll)

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'dll': {str(i): dll['_id']}}}, upsert=True)


# ---- Methods that help with deleting everything or a specific item in both the project and plugin database -------

# Deletes a project from the database
def deleteAProject(project):
    project_db.find_one_and_delete(
        {'name': project}
    )


# Deletes a project from the database
def deleteAPlugin(plugin):
    plugin_db.find_one_and_delete(
        {'name': plugin}
    )


# Deletes a poi from the plugin database
def deleteAPoiFromPlugin(plugin, newPluginDict):
    plugin_db.find_one_and_delete(
        {'name': plugin}
    )
    plugin_db.insert_one(newPluginDict)


# Delete EVERYTHING from project
def deleteDatabase():
    db.project.drop()
    db.binary.drop()
    db.static.drop()
    db.results.drop()
    db.function.drop()
    db.string.drop()
    db.variable.drop()
    db.dll.drop()
    db.struct.drop()


# Delete EVERYTHING from plugins
def deletePluginDatabase():
    db_2.plugins.drop()
