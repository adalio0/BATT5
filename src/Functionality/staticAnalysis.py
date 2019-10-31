import r2pipe
import json
import re


def staticAnalysis(filePath):
    global infile
    infile = r2pipe.open(filePath)
    infile.cmd('aaa')
    return extract_all()


def functions_analysis():
    functions = infile.cmdj("afllj")
    return functions


def string_analysis():
    strings = infile.cmdj('izj')
    return strings


def variables_analysis():
    variable = infile.cmdj('afvdj')
    formattedV = json.loads(variable)
    return formattedV


def dll_analysis():
    dlls = infile.cmd('iij')
    formattedD = json.loads(dlls)
    return formattedD


def extract_all():
    function = functions_analysis()
    string = string_analysis()
    # variable = variables_analysis()
    # dll = dll_analysis()
    # return [function, string, variable, dll]
    return [function, string]
