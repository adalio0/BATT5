import pymongo

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
db_1 = client['current_project']
current_db = db_1['current']
current_plugin_db = db_1['current_plugin']

db_2 = client['plugin_data']
plugin_db = db_2['plugins']


# Checks if static analysis has been performed on the current selected project
def checkStatic():
    flag = ''
    for c in current_db.find():
        for p in project_db.find():
            if p['_id'] == c.get('id'):
                flag = p.get('static_analysis', {}).get('performed')
    return flag

# ---- Setters for the database (sets the current project/plugin) --------------------------------------------


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


# Get the current selected plugin and sets the current plugin in the database
def setCurrentPlugin(selected):
    name = ''
    description = ''
    pointOfInterest = ''
    output = ''
    if selected:
        db_1.current_plugin.drop()
        for p in plugin_db.find():
            if p['name'] == selected:
                name = p['name']
                description = p['description']
                pointOfInterest = p['pointOfInterest']
                output = p['output']

                plugin_data = {
                    'id': p['_id']
                }
                current_outcome = current_plugin_db.insert_one(plugin_data)
    return name, description, pointOfInterest, output

# ---- Getters for the database (Gets appropriate data based on request) --------------------------------------


# Gets all of the projects that were created from the database
def getProjects():
    # deleteDatabase()
    projects = []
    for p in project_db.find():
        projects.append(p.get('name'))
    return projects


# Gets all the current plugins for the project
def getPlugins():
    # deletePluginDatabase()
    plugins = []
    for p in plugin_db.find():
        plugins.append(p.get('name'))
    return plugins


# Gets the path of the current project's file
def getCurrentFilePath():
    for c in current_db.find():
        for p in project_db.find():
            if p['_id'] == c.get('id'):
                for b in binary_db.find():
                    if b['_id'] == p.get('binary'):
                        return b.get('file')


# Gets the appropriate database
def getAppropriatePoi(poi):
    if poi == "Extract All":
        return [function_db, string_db, variable_db, dll_db]
    elif poi == "Function":
        return function_db
    elif poi == "String":
        return string_db
    elif poi == "Variable":
        return variable_db
    elif poi == "DLL":
        return dll_db


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


# Display all POI in the Analysis box
def getAllPoi(poi):
    data = []
    functions = []
    strings = []
    variables = []
    dlls = []
    for c in current_db.find():
        for p in project_db.find():
            if p['_id'] == c.get('id'):
                for s in static_db.find():
                    if s['_id'] == p.get('static_analysis', {}).get('01'):
                        for r in results_db.find():
                            if r['_id'] == s.get('results').get('01'):
                                database = getAppropriatePoi(poi)
                                for i in range(len(database)):
                                    for d in database[i].find():
                                        if r['_id'] == d.get('results_id'):
                                            content = d.get('data')
                                            try:
                                                data.append(content)
                                            except TypeError:
                                                pass
                                    if i == 0:
                                        functions.append(data)
                                    elif i == 1:
                                        strings.append(data)
                                    elif i == 2:
                                        variables.append(data)
                                    elif i == 3:
                                        dlls.append(data)
                                    data = []
    return functions[0], strings[0], variables[0], dlls[0]


# ---- Methods that save/insert data into the database -----------------------------------------------

# Gets and saves the created plugin into the database
def savePlugin(plugin):
    plugin_db.insert_one(plugin)

def saveComment(comment, poi, dropText, table):
    if dropText == 'Extract All':
        print(0)
    else:
        print(1)
    return

def saveComment(comment, poi):
    return


# Gets and saves Static Analysis results into database TODO: Take care of the overflow stuff?
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
                                for i in range(len(poi[0])):
                                    function = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'data': poi[0][i]
                                    }
                                    try:
                                        function_outcome = function_db.insert_one(function)
                                    except OverflowError:
                                        pass

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'function': {str(i): function['_id']}}}, upsert=True)

                                for i in range(len(poi[1])):
                                    string = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'data': poi[1][i]
                                    }
                                    try:
                                        string_outcome = string_db.insert_one(string)
                                    except OverflowError:
                                        pass

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'string': {str(i): string['_id']}}}, upsert=True)

                                for i in range(len(poi[2]['sp'])):
                                    variable = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'data': poi[2]['sp'][i]
                                    }
                                    try:
                                        variable_outcome = variable_db.insert_one(variable)
                                    except OverflowError:
                                        pass

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'variable': {str(i): variable['_id']}}}, upsert=True)

                                for i in range(len(poi[3])):
                                    dll = {
                                        'results_id': r['_id'],
                                        'comment': '',
                                        'data': poi[3][i]
                                    }
                                    try:
                                        dll_outcome = dll_db.insert_one(dll)
                                    except OverflowError:
                                        pass

                                    results_db.find_one_and_update(
                                        {'_id': s['_id']},
                                        {'$push': {'dll': {str(i): dll['_id']}}}, upsert=True)


# ---- Methods that help with deleting everything or a specific item in both the project and plugin database -------

# Deletes a project from the database
def deleteAProject(project):
    project_db.find_one_and_delete(
        {'name': project}
    )

    # for i in len(database):
    #     database.find_one_and_update(
    #         {'data': {'name': function}},
    #
    #
    #
    #         {'$push': {'comment': actualcomment}},
    #         upsert=False)


# Deletes a project from the database
def deleteAPlugin(plugin):
    plugin_db.find_one_and_delete(
        {'name': plugin}
    )

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


# Delete EVERYTHING from plugins
def deletePluginDatabase():
    db_2.plugins.drop()
