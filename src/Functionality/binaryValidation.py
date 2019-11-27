import r2pipe
import json
import re

def get_binary_info(filepath):
    infile = r2pipe.open(filepath)
    fileProperties = infile.cmd("ij")
    return fileProperties

