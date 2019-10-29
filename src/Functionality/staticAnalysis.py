import r2pipe
import json
import re


def staticAnalysis(filePath):
    global infile
    infile = r2pipe.open(filePath)
    infile.cmd('aaa')
    return extract_all()


def functions_analysis():
    function = infile.cmd("afllj")
    formattedF = json.loads(function)
    return formattedF


def string_analysis():
    string = infile.cmd('izj')
    formattedS = json.loads(string)
    return formattedS


def variables_analysis():
    variable = infile.cmd('afvdj')
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
