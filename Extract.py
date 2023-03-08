from git import Repo
from git import RemoteProgress
from git import rmtree
from tqdm import tqdm
import os
import subprocess
import re
import stat
import shutil
import platform
import json
import time

guidelineURL ='https://github.com/coreruleset/coreruleset'
if platform.system() == "Linux":
    guidelinePath = os.getcwd() + '/Guideline'
    guidelineCompiledPath = os.getcwd() + '/Guideline.txt'
    rulesPath = guidelinePath + '/rules'
elif platform.system() == "Windows":
    guidelinePath = os.getcwd() + '\\Guideline'
    guidelineCompiledPath = os.getcwd() + '\Guideline.txt'
    rulesPath = guidelinePath + '\\rules'

class CloneProgress(RemoteProgress):
    def __init__(self):
        super().__init__()
        self.pbar = tqdm()

    def update(self, op_code, cur_count, max_count=None, message=''):
        self.pbar.total = max_count
        self.pbar.n = cur_count
        self.pbar.refresh()

def compileGuideline():
    ## compiledGuideline consists of all the conf file compiled into 1 text file
    compiledGuideline = open(guidelineCompiledPath, 'w+')
    ## Loop through all the config files
    for filename in os.listdir(rulesPath):
        filePath = os.path.join(rulesPath, filename)
        if filePath.endswith('.conf'):
            try:
                confFile = open(filePath, 'r')
            except:
                print('Error! File : ' + filePath + ' unable to open.')
            lines = confFile.readlines()
            previous = None
            for line in lines:
                print(line)
                ## Retrieve the required content and write to a new text file#
                if previous is not None:
                	if line.startswith('SecRule') and not previous.startswith('chain'):
                   		compiledGuideline.write('\n')
                if not line.isspace() and not line.startswith('#'):
                    compiledGuideline.write(line)
                previous = line
            confFile.close()
        elif filePath.endswith('.data'):
            try:
                dataFile = open(filePath, 'r')
            except:
                print('Error! File : ' + filePath + ' unable to open.')
            filename = filePath.split('/')[-1]
            compiledGuideline.write("Filename: " + filename + "\n")
            lines = dataFile.readlines()
            for line in lines:
                if not line.isspace() and not line.startswith('#'):
                    compiledGuideline.write(line)
    compiledGuideline.close()

def compileWAF():
    test = os.system("cat /usr/share/modsecurity-crs/rules/*.conf >> /home/egglet/waf.txt")
    with open("waf.txt", "r") as input_file, open("output_file.txt", "w") as output_file:
        for line in input_file:
            if not line.startswith("#"):
                output_file.write(line)
    
def convertToJSON(input_file_name, output_file_name):
    # Open the rule file and read its content
    with open(input_file_name, "r") as file:
        content = file.read()

    # Split the content into separate rules
    rules = content.split("\n\n")

    # Create a list of dictionaries containing the rules
    data = []
    count = 0

    for rule in rules:
        fields = rule.split("\n")
        rule_data = {}
        for field in fields:
            #This is for 1-liner rules
            if "id:" in field and "phase:" in field:
                x = field.split('" "')
                name, value = x[0].split(":", 1)
                rule_data[name] = value
                y = x[1].split(",")
                for field in y:
                    if ":" in field:
                        #Split line into name and value separated by ":"
                        name, value = field.split(":", 1)
                        name = name.replace('\"', "")
                        #Remove "," in the value
                        value = value.replace(",","").replace("'", "").replace('\"', "")
                    else:
                        name = field
                        name = name.strip()
                        value = ""
                    rule_data[name] = value
                break
            if ":" in field:
                #Split line into name and value separated by ":"
                name, value = field.split(":", 1)
                name = name.replace('\"', "")
                #Remove "," in the value
                value = value.replace(",","").replace("'", "").replace('\"', "")
            else:
                name = field
                name = name.strip()
                value = ""
            #Remove:
            # extra whitespaces in front of name
            # \\ backtrailing from name
            # comma
            name = name.strip("\\").strip(",").strip()
            
            #Remove:
            # \\ backtrailing from value
            rule_data[name] = value.strip("\\")
        if len(rule_data) > 2:
            data.append(rule_data)
    # Convert the data to a JSON string
    json_data = json.dumps(data, indent=4)

    # Write the JSON string to a file
    with open(output_file_name, "w") as file:
        file.write(json_data)

def get_latest_tag(url):
    process = subprocess.Popen(["git", "ls-remote", "--tags", "--refs", url], stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()
    latest_tag = re.split(r'/|\n', stdout.decode('ascii'))[-2]
    return latest_tag

def main():
    ## If guideline does not exist, make a directory and clone the latest from github
    if not os.path.exists(guidelinePath):
        os.mkdir(guidelinePath)
        Repo.clone_from(guidelineURL,guidelinePath,progress=CloneProgress())

    ## Retrieve the hash of latest version from github
    latestTag = get_latest_tag(guidelineURL)
    
    ## Retrieve the hash of the current version downloaded locally
    try:
        repo = Repo(guidelinePath)
        currentHash = repo.head.commit.hexsha
        currentTag = repo.git.describe(tags=True)
        ## Compare hash to determine if there are any new updates to the guideline
        if latestTag == currentTag:
            print(f"The guideline is the latest version ({currentTag})!")
        else:
            shutil.rmtree(guidelinePath, ignore_errors=False)
            Repo.clone_from(guidelineURL,guidelinePath,progress=CloneProgress())
            print(f"Updated to version {latestTag}!")

    except:
        print("Please delete the folder " + guidelinePath + " manually and re-run the program")
    compileGuideline()
    compileWAF()
    convertToJSON("output_file.txt", "waf.json")
    convertToJSON("Guideline.txt", "Guideline.json")
    time.sleep(5)
    #subprocess.run(['python', 'Compare.py'])
    os.system("sudo rm -r *.png")	
    os.system("python3 Compare.py")

if __name__ == "__main__":
    latestTag = get_latest_tag(guidelineURL)
    main()
    


