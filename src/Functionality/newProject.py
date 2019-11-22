import sys
import pymongo
import r2pipe

from PyQt5 import QtWidgets
from src.GUI.python_files.popups.newProjectWind import NewProject
from src.GUI.python_files.popups.errors import ErrEmptyFields
from src.GUI.python_files.popups.errors import Errx86

properties = []
checkBinary = False

class ProjectWindow(QtWidgets.QDialog):
    def __init__(self):
        super(ProjectWindow, self).__init__()
        self.window = NewProject()
        self.window.setupUi(self)
        self.window.path_lineEdit.setDisabled(True)

        # create button pressed
        self.window.create_button.clicked.connect(self.createProject)
        # browse button pressed
        self.window.browse_button.clicked.connect(self.showFileExplorer)
        # cancel button pressed
        self.window.cancel_button.clicked.connect(self.close)

    # ---- Extracts file location -----------------------------------------------------------------------
    def showFileExplorer(self):

        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, "QFileDialog.getOpenFileName()", "",
                                                        "All Files (*);;Python Files (*.py)", options=options)
        self.window.path_lineEdit.setText(name)
        if name:
            self.setProperties()
            self.validatex86()
            if checkBinary == False:
                self.window.path_lineEdit.clear()
                self.showx86Err()
                #show error
            
                
        

    # ---- Extracts text from fields and inserts them into the project database -----------------
    def createProject(self):
        if self.window.projectName_lineEdit.text() == "":
            self.showErr()
        elif self.window.projectDescription_textEdit.toPlainText() == "":
            self.showErr()
        elif self.window.path_lineEdit.text() == "":
            self.showErr()
        else:
            # Store new project into the database
            self.insertToDatabase()

            # close window
            self.accept()
            self.close()

    # ---- Stores the created project into the database -------------------------------
    def insertToDatabase(self):
        client = pymongo.MongoClient("mongodb://localhost:27017")
        db = client['project_data']
        project_db = db['project']
        binary_db = db['binary']
        static_db = db['static']
        results_db = db['results']

        results = {
            'static_id': '',

            'associated_plugin': '',

            'function': [

            ],

            'string': [

            ],

            'variable': [

            ],

            'dll': [

            ]
        }
        results_outcome = results_db.insert_one(results)

        static_analysis = {
            'project_id': '',

            'results': {
                '01': results['_id']
            }
        }
        static_outcome = static_db.insert_one(static_analysis)

        binary = {
            'project_id': '',

            'file': self.window.path_lineEdit.text(),
            'os': properties[0],
            'binary': properties[1],
            'machine': properties[2],
            'class': properties[3],
            'bits': properties[4],
            'language': properties[5],
            'canary': properties[6],
            'crypto': properties[7],
            'nx': properties[8],
            'pic': properties[9],
            'relocs': properties[10],
            'relro': properties[11],
            'stripped': properties[12]
        }
        binary_outcome = binary_db.insert_one(binary)

        project_data = {
            'name': self.window.projectName_lineEdit.text(),

            'description': self.window.projectDescription_textEdit.toPlainText(),

            'binary': binary['_id'],

            'static_analysis': {
                'performed': False,

                '01': static_analysis['_id']
            },

            'dynamic_analysis': {
                '01': '',
            }
        }
        project_outcome = project_db.insert_one(project_data)

        binary_db.find_one_and_update(
            {'_id': binary['_id']},
            {'$set': {'project_id': project_data['_id']}}, upsert=True)
        static_db.find_one_and_update(
            {'_id': static_analysis['_id']},
            {'$set': {'project_id': project_data['_id']}}, upsert=True)
        results_db.find_one_and_update(
            {'_id': results['_id']},
            {'$set': {'static_id': static_analysis['_id']}}, upsert=True)

    def accept(self):
        super(ProjectWindow, self).accept()

    # ---- Show Error Message ------------------------------------------
    def showErr(self):
        self.windowEF = ErrEmptyFields()
        self.windowEF.show()
    def showx86Err(self):
        self.windowxF = Errx86()
        self.windowxF.show()
    #----Validate Binary x86-------------------------------------------------------
    def validatex86(self):
        global checkBinary 
        tree = self.window.properties_treeWidget
        item0 = tree.itemAt(0,0)
        item1 = tree.itemBelow(item0)
        item2 = tree.itemBelow(item1)
        
        if item2.text(1) == "AMD 64":
            checkBinary = True
            self.window.create_button.setDisabled(False)
        else:
            self.window.create_button.setDisabled(True)
        
    # ---- Displays binary data in Tree Widget -------------------------------------
    def setProperties(self):
        infile = r2pipe.open(self.window.path_lineEdit.text())
        fileProperties = infile.cmdj("ij")

        bin = fileProperties.get('bin', {})
        tree = self.window.properties_treeWidget

        # os
        item0 = tree.itemAt(0, 0)
        try:
            item0.setText(1, str(bin['os']))
            properties.append(str(bin['os']))
        except KeyError:
            item0.setText(1, "N/A")
            properties.append("N/A")

        # binary type
        item1 = tree.itemBelow(item0)
        try:
            item1.setText(1, str(bin['bintype']))
            properties.append(str(bin['bintype']))
        except KeyError:
            item1.setText(1, "N/A")
            properties.append("N/A")

        # machine
        item2 = tree.itemBelow(item1)
        try:
            item2.setText(1, str(bin['machine']))
            properties.append(str(bin['machine']))
        except KeyError:
            item2.setText(1, "N/A")
            properties.append("N/A")

        # class
        item3 = tree.itemBelow(item2)
        try:
            item3.setText(1, str(bin['class']))
            properties.append(str(bin['class']))
        except KeyError:
            item3.setText(1, "N/A")
            properties.append("N/A")

        # bits
        item4 = tree.itemBelow(item3)
        try:
            item4.setText(1, str(bin['bits']))
            properties.append(str(bin['bits']))
        except KeyError:
            item4.setText(1, "N/A")
            properties.append("N/A")

        # language
        item5 = tree.itemBelow(item4)
        try:
            item5.setText(1, str(bin['lang']))
            properties.append(str(bin['lang']))
        except KeyError:
            item5.setText(1, "N/A")
            properties.append("N/A")

        # canary
        item6 = tree.itemBelow(item5)
        try:
            item6.setText(1, str(bin['canary']))
            properties.append(str(bin['canary']))
        except KeyError:
            item6.setText(1, "N/A")
            properties.append("N/A")

        # crypto
        item7 = tree.itemBelow(item6)
        try:
            item7.setText(1, str(bin['crypto']))
            properties.append(str(bin['crypto']))
        except KeyError:
            item7.setText(1, "N/A")
            properties.append("N/A")

        # nx
        item8 = tree.itemBelow(item7)
        try:
            item8.setText(1, str(bin['nx']))
            properties.append(str(bin['nx']))
        except KeyError:
            item8.setText(1, "N/A")
            properties.append("N/A")

        # pic
        item9 = tree.itemBelow(item8)
        try:
            item9.setText(1, str(bin['pic']))
            properties.append(str(bin['pic']))
        except KeyError:
            item9.setText(1, "N/A")
            properties.append("N/A")

        # relocs
        item10 = tree.itemBelow(item9)
        try:
            item10.setText(1, str(bin['relocs']))
            properties.append(str(bin['relocs']))
        except KeyError:
            item10.setText(1, "N/A")
            properties.append("N/A")

        # relro
        item11 = tree.itemBelow(item10)
        try:
            item11.setText(1, str(bin['relro']))
            properties.append(str(bin['relro']))
        except KeyError:
            item11.setText(1, "N/A")
            properties.append("N/A")

        # stripped
        item12 = tree.itemBelow(item11)
        try:
            item12.setText(1, str(bin['stripped']))
            properties.append(str(bin['stripped']))
        except KeyError:
            item12.setText(1, "N/A")
            properties.append("N/A")


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ProjectWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
