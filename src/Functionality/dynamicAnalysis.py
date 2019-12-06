import r2pipe
import json

def refactoredDynamic(filepath, dictList):
    infile = r2pipe.open(filepath)  # open file
    infile.cmd("aaa")
    #infile.cmd("ood")  # open in debug mode
    for i in range(len(dictList)):  # iterate over list of functions
        infile.cmd("ood")  # open in debug mode
        breakpoint = dictList[i]['fName'] # need to handle entry0 special case
        infile.cmd("db " + breakpoint)  # first set the breakpoint
        infile.cmd("dc") #continue to run
        infile.cmd("dcr") #get values at this point
        returnVal = infile.cmd("dr rax")
        returnVal = returnVal.rstrip("\n")
        dictList[i]['retValue'] = returnVal
        # start running after breakpoint get arguments first
        templistOfVals = []
        templistOfLoc =[]
        #for arguments if argNum is 0 this will skip
        try:
            for j in range(dictList[i]['argNum']):
                if dictList[i]['argNum'] > 0 and breakpoint != 'entry0':
                    try:
                        argumentName = dictList[i]['argName'][j]
                        commandToVal = infile.cmd("afvd " + argumentName)
                        commandList = commandToVal.split(" ")
                        validCommand = commandList[0] + "j " + commandList[1] + " " + commandList[2]
                        lineWithval = infile.cmd(validCommand)
                        formattedVal = json.loads(lineWithval)
                        templistOfVals.append(str(formattedVal[0]['value']))
                    except IndexError:
                        templistOfVals.append('0')
                else:
                    templistOfVals.append('0')
                dictList[i]['argVal'] = templistOfVals
        except IndexError:
            continue

        #for local variables

        for k in range(dictList[i]['locNum']):
            if dictList[i]['locNum'] > 0:
                try:
                    argumentName = dictList[i]['locName'][j]
                    commandToVal = infile.cmd("afvd " + argumentName)
                    commandList = commandToVal.split(" ")
                    validCommand = commandList[0] + "j " + commandList[1] + " " + commandList[2]
                    lineWithval = infile.cmd(validCommand)
                    formattedVal = json.loads(lineWithval)
                    templistOfLoc.append(str(formattedVal[0]['value']))
                except IndexError:
                    templistOfLoc.append('0')
            else:
                templistOfLoc.append('0')
            dictList[i]['locVal'] = templistOfLoc

    infile.cmd("db-*")
    return dictList
