import r2pipe
import json
import re


def staticAnalysis(filePath,poi):
    infile = r2pipe.open(filePath)
    imports = infile.cmd(poi)
    formatted = json.loads(imports) # formats json output into a python dictionary
    return formatted
