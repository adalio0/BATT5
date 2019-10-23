import r2pipe
import json
import re

def get_binary_info(filepath):
    infile = r2pipe.open(filepath)
    infile.syscmd("rabin2 -I " + filepath "  > binaryinfo.txt")

