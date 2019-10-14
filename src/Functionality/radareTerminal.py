# -*- coding: utf-8 -*-
"""
BATT5 Terminal program
This program contains stuff

@author: rivas
"""
import r2pipe as r2
import sys

class Terminal(object):
    # constructor, initialize and launce terminal
    def __init__(self, b): 
        # location of binary file that will be analyzed
        self.binaryPath = b
        self.openBinary()
        self.launchTerminal()
    
    def setBinaryLocation(self, b):
        self.binaryPath = b
        
    # might be used for for when interfacing with GUI
    def getBinaryLocation(self):
        return self.binaryPath
    
    def openBinary(self):
        try:
            self.r = r2.open(self.binaryPath)
            print(self.binaryPath, 'opened')
        except:
            print('Error opening binary:', self.binaryPath)
            
    def launchTerminal(self):
        while True:
            command = input('BATT5$ ')
            
            if(command == 'exit'):
                print('goodbye!')
                break
            else:
                try:
                    rc = self.r.cmd(command)
                    print('that worked')
                except:
                    print('that didnt work')

t = Terminal('PING.EXE')
#r = r2.open('PING.EXE')
#print( r.cmd('pdf') )