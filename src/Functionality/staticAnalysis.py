import r2pipe
import json
import re



def staticAnalysis(filePath, poi):
    global infile
    infile = r2pipe.open(filePath)
    infile.cmd('aaa')
    # print(infile.cmd('afll'))
    # imports = infile.cmd(poi)
    # formatted = json.loads(imports) # formats json output into a python dictionary
    # return formatted
    if poi == 'String':
        string_analysis()
    elif poi == 'Variable':
        variables_analysis()
    elif poi == 'DLL':
        dll_analysis()
    elif poi == 'Function':
        functions_analysis()
    elif poi == 'Extract All':
        extract_all()


def string_analysis():
    infile.cmd('iz > strings.txt')


def dll_analysis():
    infile.cmd('ii > dlls.txt')


def functions_analysis():
    infile.cmd('afll > functions.txt')


def variables_analysis():
    infile.cmd('afvd > vars.txt')


def extract_all():
    string_analysis()
    dll_analysis()
    functions_analysis()
    variables_analysis()
