import r2pipe
import json


# The dynamic analysis function will receive the filepath to be analyzed
# As well a list of points of interest(at this point this is a list of functions)
# The functions will be set as break points, it should return a structure with the function name all the local variables
# the arguments and their values at the breakpoint then after the return call



# def dynamicAnalysis(filePath, funcList):
#     # infile = r2pipe.open(filePath, ['-d', '-e', 'dbg.profile=profile.rr2']) #open file, will do only once
#     infile = r2pipe.open(filePath)
#     # infile.cmd('e dbg.profile=robot.rr2')  # this line should configure things properly should input be required
#     infile.cmd("aaa") # entire analysis is needed for full functionality
#     progress = [] # empty list to attach things too
#     for i in range(len(funcList)): # iterate over list of functions
#         curntFunc = funcList[i]
#         progress.append("Function Name:")
#         progress.append(curntFunc)
#         infile.cmd("ood")   # open in debug mode
#         breakpointString = "db " + str(curntFunc)
#         infile.cmd(breakpointString) # first set the breakpoint
#         infile.cmd("dc")    # continue to run until breakpoint is hit, there may be some input required which still not sure where to pass it
#         progress.append("Hit breakpoint @ " + curntFunc)
#         argsnvar = infile.cmd("afvd")   # get args and local vars at this point
#         progress.append("----------Initial Values of Args and Variables----------")
#         progress.append(argsnvar)   # put args on list
#         infile.cmd("dcr")   # continue execution until return call
#         returnvals = infile.cmd("afvd")#values at the end
#         progress.append("----------Final Values of Args and Variables----------")
#         progress.append(returnvals)     # end values
#         stack = infile.cmd("x@rsp")     # peek in the stack, some other values may be elswhere will have to modify
#         progress.append("----------STACK----------")
#         progress.append(stack)  # add stack to list
#         rax = infile.cmd("dr rax")#return value
#         progress.append("----------RETURN VALUE----------")
#         progress.append(rax)    # put in list
#         progress.append("--------------------------------")
#         # at this point process is done so the breakpoint needs to be removed for next thing
#         infile.cmd("db-*")  # remove all breakpoints
#     return progress




def new_dynamic(filePath, funcList):
    keys = ['fName', 'argNum', 'argName', 'argType', 'argVal', 'retName', 'retType', 'retValue', 'locName', 'locType', 'locNum']
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

def getValues(filepath, dictList):
    infile = r2pipe.open(filepath)  # open file
    infile.cmd("aaa")
    for i in range(len(dictList)):  # iterate over list of functions
        infile.cmd("ood")  # open in debug mode
        breakpointString = "db " + (dictList[i]['fName'].encode('utf-8'))
        infile.cmd(breakpointString)  # first set the breakpoint
        infile.cmd("dc") #continue to run
        infile.cmd("dcr") #get values at this point
        returnVal = infile.cmd("dr rax")
        returnVal = returnVal.rstrip("\n").encode('utf-8')
        # start running after breakpoint get arguments first
        templistOfVals = []
        templistOfLoc =[]
        #for arguments
        for j in range(dictList[i]['argNum']):
            #set return value
            dictList[i]['retVal'] = returnVal
            commandToVal = infile.cmd("afvd " + dictList[i]['argName'][j])
            commandList = commandToVal.split(" ")
            validCommand = commandList[0] + "j " + commandList[1] + " " + commandList[2]
            lineWithval = infile.cmd(validCommand)
            formattedVal = json.loads(lineWithval)
            templistOfVals.append(formattedVal[0]['value'])
            dictList[i]['argVal'] = templistOfVals
        #for local variables
        for k in range(dictList[i]['locNum']):
            commandToVal = infile.cmd("afvd " + dictList[i]['locName'][j])
            commandList = commandToVal.split(" ")
            validCommand = commandList[0] + "j " + commandList[1] + " " + commandList[2]
            lineWithval = infile.cmd(validCommand)
            formattedVal = json.loads(lineWithval)
            templistOfLoc.append(formattedVal[0]['value'])
            dictList[i]['locVal'] = templistOfLoc


        infile.cmd("db-*")
    return dictList