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




def dynamicAnalysis(filepath, dictList):
    print(dictList)
    infile = r2pipe.open(filepath)  # open file
    infile.cmd("aaa")
    #infile.cmd("ood")  # open in debug mode
    for i in range(len(dictList)):  # iterate over list of functions
        infile.cmd("ood")  # open in debug mode
        breakpoint = dictList[i]['fName']
        print(breakpoint)
        if breakpoint == 'entry0':
            i+=1
        if breakpoint == 'main':
            break
        breakpointString = "db " + (dictList[i]['fName'])
        infile.cmd(breakpointString)  # first set the breakpoint
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
            for j in range(dictList[i]['argNum'][0]):
                print("made it here")
                #set return value
                #dictList[i]['retValue'] = returnVal.decode('utf-8')
                print(type(dictList[i]['retValue']))
                argumentName = dictList[i]['argName'][j]
                print(argumentName)
                argumentString = argumentName.decode('utf-8')
                print(argumentString)
                commandToVal = infile.cmd("afvd " + argumentString)
                # if not commandToVal:
                #     print("I go here")
                #     infile.cmd("dcr")
                #     testCommand = "afvd " + argumentString
                #     print(testCommand)
                #     commandToVal = infile.cmd("afvd " + argumentString)
                #     print(commandToVal)
                commandList = commandToVal.split(" ")
                print(commandList)
                validCommand = commandList[0] + "j " + commandList[1] + " " + commandList[2]
                print(validCommand)
                lineWithval = infile.cmd(validCommand)
                formattedVal = json.loads(lineWithval)
                templistOfVals.append(formattedVal[0]['value'])
                dictList[i]['argVal'] = templistOfVals
        except (IndexError, TypeError):
            continue
        #for local variables
        try:
            for k in range(int(dictList[i]['locNum'][0])):
                commandToVal = infile.cmd("afvd " + dictList[i]['locName'][k])
                print(commandToVal)
                commandList = commandToVal.split(" ")
                print(commandList)
                validCommand = commandList[0] + "j " + commandList[1] + " " + commandList[2]
                lineWithval = infile.cmd(validCommand)
                formattedVal = json.loads(lineWithval)
                templistOfLoc.append(formattedVal[0]['value'])
                dictList[i]['locVal'] = templistOfLoc
        except(IndexError, TypeError):
            continue
        infile.cmd("db-*")
    print("Succesfully ended")
    return dictList

