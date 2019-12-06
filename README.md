# BATT5
<b>Binary Analysis Tool by Team 5 (BATT5)<br></b>
The Binary Analysis Tool by Team 5 (BATT5) is a reverse engineering tool meant to analyze 32-bit (x86) binary
(executable) files. Using Radare2, this tool uses Static Analysis to extract points of interests (functions, strings,
variables, and DLL's) and allows users to uncover attributes of these points of interest (POI's) through the use of
Dynamic Analysis.<br>
<br>
The BATT5 system also the user to create and define plugins that filter specific POI's and extend the functionality of
BATT5. Users can create these plugins by using XML files that follow our XML schemas or by using the system's GUI.<br>
<br>
<b>Dependency Installation</b><br>
Although most BATT5 dependencies could be installed using pip, this is not the case for all dependencies.<br>
Instructions on installing dependencies that require additional steps will be specified in this section. <br><br>
To install all BATT5 dependencies:<br>
1) Clone this repository running <b>$git clone https://github.com/adalio0/BATT5.git </b><br>
2) At the root of this repository, run <b>$pip install -r requirements.txt</b>. This will install all python dependencies of BATT5.<br>
3) To install radare2, clone its repository and follow the installation instructions specified in radare2's <b>README.</b><br>
*radare2 Repository: https://github.com/radareorg/radare2 <br>
*NOTE: radare2 must be installed through Github instructions, running <b>$sudo-apt install radare2</b> will provide you with a version of Radare2 that is not fully functional.<br>
4) To install mongodb, download and install the MongoDB Community Server package.<br>
*Download Link: https://www.mongodb.com/download-center/community <br>
*Note, mongodb must be running in the background during BATT5's runtime. This could be done by running <b>$sudo service mongod start</b>.<br>

<b>Dependencies</b><br>
listed below are the dependencies used in the BATT5 system: <br>
- <b>PIP DEPENDENCIES</b><br>
- r2pipe <br>
- pymongo <br>
- PyQt5 <br>
- QtPy <br>
- xmljson <br>
- xmlschema <br>
- fbs <br><br>
- <b>OTHER DEPENDENCIES</b><br>
- radare2 <br>
- mongodb (server - mongod must be running) <br>
<br>

<b>Running BATT5</b><br>
In its current implementation, the system's executable is in the form of a bash script that runs the primery Python file (uiControl.py). To run BATT5, you must have all dependencies installed. Once this is done, perform the following commands at the root directory of BATT5:<br>
<b>$chmod +x BATT5.sh</b><br>
<b>$./BATT5.sh</b>
