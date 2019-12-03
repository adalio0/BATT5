import r2pipe
import base64
import json

def staticAnalysis(filePath):
    global infile
    infile = r2pipe.open(filePath)
    infile.cmd('aaa')
    return extract_all()

def functions_analysis():
    functions = infile.cmdj('afllj')
    return functions

def string_analysis():
    strings = infile.cmdj('izzj')
    # decode from base 64
    for i in range(len(strings)):
        try:
            strings[i]['string'] = base64.b64decode(strings[i]['string']).decode("utf-8")
        except:
            pass
    return strings

def variables_analysis():
    variable = infile.cmdj('afvj')
    return variable

def dll_analysis():
    dlls = infile.cmdj('iij')
    return dlls

def struct_analysis():
    structs = infile.cmdj('tsj')
    return structs

def packet_protocol_analysis():
    # TODO
    protocols = []
    return protocols

def extract_all():
    function = functions_analysis()
    string = string_analysis()
    variable = variables_analysis()
    dll = dll_analysis()
    struct = struct_analysis()
    return [function, string, variable, dll, struct]

def historicAnalysis(filePath, funcList):
    keys = ['fName', 'argNum', 'argName', 'argType', 'argVal', 'retName', 'retType', 'retValue', 'locName', 'locType', 'locNum', 'locVal']
    # will be used to add each function dictionary
    dictList = []
    argCounter = 0
    locCounter = 0
    # create a dictionary with keys that correspond to fields needed for the functions
    funD = dict.fromkeys(keys, [])
    infile = r2pipe.open(filePath)  # open file
    infile.cmd("aaa")  # initial analysis

    # start analysis process
    for i in range(len(funcList)):
        funD['fName'] = (funcList[i])
        funInfo = infile.cmd("afvj @ " + funcList[i])
        formatInfo = json.loads(funInfo)

        for key in formatInfo.keys():
            tempList = formatInfo[key]
            #print(tempList)
            argNames = []
            argTypes = []
            localVarNames = []
            localVarTypes = []
            for j in range(len(tempList)):
                if tempList[j]['kind'] == 'reg':
                    argCounter += 1
                    funD['argNum'] = argCounter
                    argNames.append(tempList[j]['name'].encode('utf-8'))
                    argTypes.append(tempList[j]['type'].encode('utf-8'))
                    funD['argName'] = argNames
                    funD['argType'] = argTypes
                if tempList[j]['kind'] == 'var':
                    locCounter += 1
                    funD['locNum'] = locCounter
                    localVarNames.append(tempList[j]['name'].encode('utf-8'))
                    localVarTypes.append(tempList[j]['type'].encode('utf-8'))
                    funD['locName'] = localVarNames
                    funD['locType'] = localVarTypes

        argCounter = 0
        locCounter = 0

        dictList.append(funD)
        funD = dict.fromkeys(keys, [])

    return dictList
