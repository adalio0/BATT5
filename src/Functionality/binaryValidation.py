import r2pipe
import json
import re

def get_binary_info(filepath):
    infile = r2pipe.open(filepath)
    fileProperties = infile.cmdj("ij")
    return fileProperties

