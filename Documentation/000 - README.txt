# BATT5
Binary Analysis Tool by Team 5 (BATT5)
The Binary Analysis Tool by Team 5 (BATT5) is a reverse engineering tool meant to analyze 32-bit (x86) binary
(executable) files. Using Radare2, this tool uses Static Analysis to extract points of interests (functions, strings,
variables, and DLL's) and allows users to uncover attributes of these points of interest (POI's) through the use of
Dynamic Analysis

The BATT5 system also the user to create and define plugins that filter specific POI's and extend the functionality of
BATT5. Users can create these plugins by using XML files that follow our XML schemas or by using the system's GUI.

Dependency Installation
Although most BATT5 dependencies could be installed using pip, this is not the case for all dependencies.
Instructions on installing dependencies that require additional steps will be specified in this section.
To install all BATT5 dependencies:
1) Clone this repository running $git clone https://github.com/adalio0/BATT5.git

2) At the root of this repository, run $pip install -r requirements.txt. This will install all python dependencies of BATT5.

3) To install radare2, clone its repository and follow the installation instructions specified in radare2's README.
*radare2 Repository: https://github.com/radareorg/radare2 
*NOTE: radare2 must be installed through Github instructions, running $sudo-apt install radare2 will provide you with a version of Radare2 that is not fully functional.
4) To install mongodb, download and install the MongoDB Community Server package.
*Download Link: https://www.mongodb.com/download-center/community
*Note, mongodb must be running in the background during BATT5's runtime. This could be done by running $sudo service mongod start.

Dependencies
listed below are the dependencies used in the BATT5 system:
- PIP DEPENDENCIES
- r2pipe
- pymongo
- PyQt5
- QtPy
- xmljson
- xmlschema
- fbs
- OTHER DEPENDENCIES
- radare2
- mongodb (server - mongod must be running)
