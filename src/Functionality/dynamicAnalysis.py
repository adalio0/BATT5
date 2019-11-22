import r2pipe
import json


# The dynamic analysis function will receive the filepath to be analyzed
# As well a list of points of interest(at this point this is a list of functions)
# The functions will be set as break points, it should return a structure with the function name all the local variables
# the arguments and their values at the breakpoint then after the return call



def dynamicAnalysis(filePath, funcList):
    # infile = r2pipe.open(filePath, ['-d', '-e', 'dbg.profile=profile.rr2']) #open file, will do only once
    infile = r2pipe.open(filePath)
    # infile.cmd('e dbg.profile=robot.rr2')  # this line should configure things properly should input be required
    infile.cmd("aaa") # entire analysis is needed for full functionality
    progress = [] # empty list to attach things too
    for i in range(len(funcList)): # iterate over list of functions
        curntFunc = funcList[i]
        progress.append("Function Name:")
        progress.append(curntFunc)
        infile.cmd("ood")   # open in debug mode
        breakpointString = "db " + str(curntFunc)
        infile.cmd(breakpointString) # first set the breakpoint
        infile.cmd("dc")    # continue to run until breakpoint is hit, there may be some input required which still not sure where to pass it
        progress.append("Hit breakpoint @ " + curntFunc)
        argsnvar = infile.cmd("afvd")   # get args and local vars at this point
        progress.append("----------Initial Values of Args and Variables----------")
        progress.append(argsnvar)   # put args on list
        infile.cmd("dcr")   # continue execution until return call
        returnvals = infile.cmd("afvd")#values at the end
        progress.append("----------Final Values of Args and Variables----------")
        progress.append(returnvals)     # end values
        stack = infile.cmd("x@rsp")     # peek in the stack, some other values may be elswhere will have to modify
        progress.append("----------STACK----------")
        progress.append(stack)  # add stack to list
        rax = infile.cmd("dr rax")#return value
        progress.append("----------RETURN VALUE----------")
        progress.append(rax)    # put in list
        progress.append("--------------------------------")
        # at this point process is done so the breakpoint needs to be removed for next thing
        infile.cmd("db-*")  # remove all breakpoints
    return progress

def new_dynamic(filePath,funcList):

    keys = ['fName','args','argType','argVal','retName','retType','retValue']
    #create a dictionary with keys that correspond to fields needed for the functions
    funD = dict.fromkeys(keys,[])




