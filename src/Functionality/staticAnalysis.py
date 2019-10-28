import r2pipe
import json
import re
import pymongo


client = pymongo.MongoClient("mongodb://localhost:27017")
db = client['current_project']
current = db['current']

for x in current.find():
    static_ = x.get('static_analysis', {}).get('uncovered_poi', {})


def staticAnalysis(filePath):
    global infile
    infile = r2pipe.open(filePath)
    infile.cmd('aaa')
    return extract_all()


def functions_analysis():
    return infile.cmd("afllj")


def string_analysis():
    strings = infile.cmd('izj')
    formattedS = json.loads(strings)
    return formattedS


def variables_analysis():
    variables = infile.cmd('afvdj')
    formattedV = json.loads(variables)
    return formattedV


def dll_analysis():
    dlls = infile.cmd('iij')
    formattedJ = json.loads(dlls)
    return formattedJ


def extract_all():
    function = functions_analysis()
    string = string_analysis()
    variable = variables_analysis()
    dll = dll_analysis()
    return function, string, variable, dll
