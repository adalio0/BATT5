# -*- coding: utf-8 -*-
"""
BATT5 Terminal program
This program contains stuff

@author: rivas
"""
import r2pipe as r2

class Terminal(object):
    # constructor, initialize and launce terminal
    def __init__(self, b): 
        # location of binary file that will be analyzed
        self.binaryPath = b
        self.openBinary()
        # analyze binary file
        #self.r.cmd('aaa')
        self.launchTerminal()
        
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
                print('exiting...')
                break
            else:
                try:
                    print( self.r.cmd(command) )
                except:
                    print('unable to execute command:', command)

term = Terminal('PING.EXE')
