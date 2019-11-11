import r2pipe

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
    return strings


def variables_analysis():
    variable = infile.cmdj('afvj')
    return variable


def dll_analysis():
    dlls = infile.cmdj('iij')
    return dlls


def extract_all():
    function = functions_analysis()
    string = string_analysis()
    variable = variables_analysis()
    dll = dll_analysis()
    return [function, string, variable, dll]
