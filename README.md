# BATT5
<b>Software II Team 5 project.<br><br></b>

Language: Python<br>
GUI Library: pyqt<br><br>

(See srs for reference)<br>
Outside and windows: Alain<br>
Project tab: Juan<br>
Analysis tab: Adal<br>
Plugins tab: Mark<br>
POI's tab: Andrea<br>
Documentation tab: Ana<br>

# Everything you need to know about branches (hopefully)

To create a new branch form the command line:
  1. git checkout -b "name_of_branch" <br>
To create a new branch from github is simple just follow the steps it gives you. <br>

<b> THIS IS IMPORTANT SO YOU DON'T PUSH TO MASTER </b> <br>

To change to the new branch type in your command line:
  1. git pull (from master) <br>
  2. git fetch (to update the branches) <br>
    a. (optional) git branch -v -a, to check if all the branches are showing up. Looks something like this (branches will differ) <br>
        remotes/origin/HEAD           -> origin/master <br>
        remotes/origin/Projects       b91dc39 Projects tab initial commit <br>
        remotes/origin/master         abc6bd0 Run gui through uicontrol.py <br>
  3. git checkout -b custom_name origin/name_of_branch <br>
    a. custom_name is just what you would like to call it <br>
  4. git status <br>
    a. This is to make sure you are in the correct branch, it will appear in the top. <br>
  5. Done! Now you can continue as normal. <br>
If you would like to go back to master -> git checkout master <br>
If you would like to go back to the branch you created -> git checkout <br>

<b>How to install QtDesginer (Assuming you have anaconda installed):</b> <br>
1. Have python3 installed, if you don't go here: https://www.python.org/downloads/ <br>
2. Go to your command line and put this command: <i>pip install pyqt5-tools --pre</i> <br>
3. Now you should be able to open up with this command: <i>Designer</i> <br>

<b>Link to tutorial for QtDesigner:</b> https://youtu.be/Dmo8eZG5I2w

# To checkout a branch, use the follow commands<br>

#first time: make origin/branchname locally available as localname<br>
#localname = whatever name you want to give to the branch<br>
#origin/branchname = name of branch in the repo<br>
git checkout -b localname origin/branchname <br>
<br>
#othertimes <br>
git checkout localname <br>
<br>
git push origin<br>
