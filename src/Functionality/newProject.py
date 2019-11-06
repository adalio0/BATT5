import sys
import pymongo
import r2pipe

from PyQt5 import QtWidgets
from src.GUI.python_files.popups.newProjectWind import NewProject
from src.GUI.python_files.popups.errors import ErrEmptyFields


class ProjectWindow(QtWidgets.QDialog):
    def __init__(self):
        super(ProjectWindow, self).__init__()
        self.window = NewProject()
        self.window.setupUi(self)

        # create button pressed
        self.window.create_button.clicked.connect(self.createProject)
        # browse button pressed
        self.window.browse_button.clicked.connect(self.showFileExplorer)
        # cancel button pressed
        self.window.cancel_button.clicked.connect(self.close)

    # ---- Extracts File Location -----------------------------------------------------------------------
    def showFileExplorer(self):
        name, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open File')
        self.window.path_lineEdit.setText(name)
        self.getProperties()

    # ---- Extracts Text From Fields and Assigns Them To Project Object and creates xml file -------
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

        # Get properties of the binary with the current project
        # properties = \
        p = self.getProperties()

        binary = {
            'project_id': '',

            'file': self.window.path_lineEdit.text(),
            'os': str(p['os']),
            'binary': str(p['bintype']),
            'machine': str(p['machine']),
            'class': str(p['class']),
            'bits': str(p['bits']),
            'language': str(p['lang']),
            'canary': str(p['canary']),
            'crypto': str(p['crypto']),
            'nx': str(p['nx']),
            'relocs': str(p['relocs']),
            'stripped': str(p['stripped']),
            'relro': str(p['relro'])
        }
        binary_outcome = binary_db.insert_one(binary)

        project_data = {
            'name': self.window.projectName_lineEdit.text(),

            'description': self.window.projectDescription_textEdit.toPlainText(),

            'binary': binary['_id'],

            'static_analysis': {
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

    # ---- Show Error Message ---------------------------------
    def showErr(self):
        self.windowEF = ErrEmptyFields()
        self.windowEF.show()

    # ---- Sets Data To Project Object and Displays it in Tree Widget -------------------------------------
    def getProperties(self):
        infile = r2pipe.open(self.window.path_lineEdit.text())
        properties = infile.cmdj("ij")

        bin = properties.get('bin', {})
        tree = self.window.properties_treeWidget

        # os
        item0 = tree.itemAt(0, 0)
        item0.setText(1, bin['os'])
        # binary type
        item1 = tree.itemBelow(item0)
        item1.setText(1, bin['bintype'])
        # machine
        item2 = tree.itemBelow(item1)
        item2.setText(1, bin['machine'])
        # class
        item3 = tree.itemBelow(item2)
        item3.setText(1, bin['class'])
        # bits
        item4 = tree.itemBelow(item3)
        try:
            item4.setText(1, str(bin['bits']))
        except KeyError:
            item4.setText(1, "Does not exist")
        # language
        item5 = tree.itemBelow(item4)
        item5.setText(1, str(bin['lang']))
        # new item
        item6 = tree.itemBelow(item5)
        item6.setText(1, "do not need this")
        # canary
        item7 = tree.itemBelow(item6)
        item7.setText(1, str(bin['canary']))
        # crypto
        item8 = tree.itemBelow(item7)
        item8.setText(1, str(bin['crypto']))
        # nx
        item9 = tree.itemBelow(item8)
        item9.setText(1, str(bin['nx']))
        # pic
        item10 = tree.itemBelow(item9)
        item10.setText(1, str(bin['pic']))
        # relocs
        item11 = tree.itemBelow(item10)
        item11.setText(1, str(bin['relocs']))
        # relro
        item12 = tree.itemBelow(item11)
        try:
            item12.setText(1, str(bin['relro']))
        except KeyError:
            item12.setText(1, "Does not exist")
        # stripped
        item13 = tree.itemBelow(item12)
        item13.setText(1, str(bin['stripped']))

        return bin


def main():
    app = QtWidgets.QApplication(sys.argv)
    application = ProjectWindow()
    application.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
