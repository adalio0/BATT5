# -*- coding: utf-8 -*-

import r2pipe as r2
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QLineEdit
from PyQt5.QtWidgets import QTextBrowser


class Terminal(object):
    # constructor, initialize and launce terminal
    def __init__(self, b, pIn, pOut):
        # set attributes
        self.binaryPath = b
        # text boxes that will take in input as well as return output
        self.promptIn = pIn
        self.promptOut = pOut
        # function to prepare binary
        self.openBinary()
        # self.launchTerminal()

    # might be used for for when interfacing with GUI
    def getBinaryLocation(self):
        return self.binaryPath

    def openBinary(self):
        self.promptOut.clear()
        try:
            # open binary file
            self.r = r2.open(self.binaryPath)
            # analyze binary file
            self.r.cmd('aaa')
            outStr = 'Analyzing binary: ' + self.binaryPath + '\n'

        except:
            outStr = 'Error opening binary: ' + self.binaryPath + '\n'

        finally:
            self.promptOut.insertPlainText(outStr)

    def _displayOutput(self, out):
        self.promptOut.insertPlainText(out)
        self.promptOut.verticalScrollBar().setValue(self.promptOut.verticalScrollBar().maximum())

    def processInput(self, command_in):
        self.promptOut.insertPlainText('>>> ' + command_in + '\n')
        try:
            cmd = self.r.cmd(command_in)
            self._displayOutput(cmd)

        except:
            self.promptOut.insertPlainText('unable to execute command: ' + command_in + '\n')
