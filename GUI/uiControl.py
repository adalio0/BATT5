from PyQt5.QtWidgets import QMessageBox
from GUI.ui import *
import sys
import os


class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(ApplicationWindow,self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        # Projects tab functionality
        self.ui.browse_button.clicked.connect(self.browsy)
        self.ui.save_button.clicked.connect(self.savemsg)
    # project tab functions for buttons etc..
    def browsy(self):
        # os.subprocess.Popen(r'explorer')
        QMessageBox.about(self, "Project Manager", "Select Path")

    def savemsg(self):
        QMessageBox.about(self, "Project Manager", "Project Saved Successfully")

def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ApplicationWindow()
    application.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
