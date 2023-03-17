import json
from tqdm import tqdm
import os
import subprocess
import re
import stat
import shutil
import platform
from distutils.version import LooseVersion
#PDF Essentials
import pandas as pd
import matplotlib
from pylab import title, figure, xlabel, ylabel, xticks, bar, legend, axis, savefig
from fpdf import FPDF
import matplotlib.pyplot as plt
import numpy as np
#Date time
from datetime import datetime
import unicodedata
import requests
from Extract import get_latest_tag

guidelineURL ='https://github.com/coreruleset/coreruleset'

#Open the formatted JSON file to be used for comparison
def open_json(file):
    with open(file, "r") as file:
        file_data = json.load(file)
        return file_data
        
#Calculate guideline scoring
def extract_score(rule):
    anomaly_score = None
    severity = None
    setvar = None
    if "severity" in rule:
        severity = rule["severity"]
    if "setvar" in rule:
        setvar = rule["setvar"]
        if "anomaly_score_" in setvar:
            pl_match = re.search("pl\d+", setvar)
            if pl_match:
                anomaly_score = int(pl_match.group(0)[2:])
    return anomaly_score, severity

#Function can be used to check if rule exists on WAF. If exists, return index. Else return -1
def return_Index(i):
    index = -1
    ruleID = guideline[i].get("id")
    for j, obj in enumerate(waf):
        if obj.get("id") == ruleID and ruleID is not None:
            index = j
            break
    return index

#Generate Pie Chart: x = part of total, y = total
def pie_chart(x, y, xlabel, ylabel, title1):
    #clear the previous plot
    plt.clf()
    if x != 0:
        # Calculate the proportion of variable1 and variable2
        proportions = [x, y - x]
        # Define the labels for the pie chart
        labels = [xlabel, ylabel]
        # Define the colors for the pie chart
        colors = ['#ff9999','#66b3ff']
        #print(y, x)
    elif x == 0:
        proportions = [y]
        labels = [ylabel]
        colors = ['#66b3ff']
    # Create the pie chart
    plt.pie(proportions, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    # Add a title to the pie chart
    #plt.title(title1)
    filename = 'pie_chart.png'
    if os.path.isfile(filename):
        i = 1
        while os.path.isfile(f'pie_chart_{i}.png'):
            i += 1
        filename = f'pie_chart_{i}.png'
    plt.savefig(filename)
    
def calculate_weighted_scores(file_path):
    # Open the formatted JSON file to be used for comparison
    def open_json(file):
        with open(file, "r") as file:
            file_data = json.load(file)
            return file_data

    def extract_score(rule):
        anomaly_score = None
        paranoia_level = None
        severity = None
        setvar = None
        tag = None
        if "severity" in rule:
            severity = rule["severity"]
        if "setvar" in rule:
            setvar = rule["setvar"]
            if "anomaly_score_" in setvar:
                pl_match = re.search("pl\d+", setvar)
                if pl_match:
                    anomaly_score = int(pl_match.group(0)[2:])
            elif "paranoia_level=" in setvar:
                pl_match = re.search("\d+", setvar)
                if pl_match:
                    paranoia_level = int(pl_match.group(0))
            elif "tag" in rule:
                tag = rule["tag"]
                if "paranoia-level/" in tag:
                    pl_match = re.search("\d+", tag)
                    if pl_match:
                        paranoia_level = int(pl_match.group(0))

        return anomaly_score, paranoia_level, severity

    guideline = open_json(file_path)
    #print("Number of rules:", len(guideline))
    total_weighted_score = 0
    w1 = 0.2 # weight for anomaly score
    w2 = 0.2 # weight for paranoia level
    w3 = 0.5 # weight for severity

    for rule in guideline:
        anomaly_score, paranoia_level, severity = extract_score(rule)
        # Skip over rules without anomaly score, paranoia level, and severity
        if anomaly_score is None and paranoia_level is None and severity is None:
            continue
        # Calculate weighted score according to anomaly score, paranoia level, and severity
        weighted_score = 0
        if anomaly_score is not None:
            weighted_score += (anomaly_score * w1)
        if paranoia_level is not None:
            weighted_score += (paranoia_level * w2)
        if severity == "CRITICAL":
            weighted_score += (5 * w3)
        elif severity == "ERROR":
            weighted_score += (4 * w3)
        elif severity == "WARNING":
            weighted_score += (3 * w3)
        elif severity == "NOTICE":
            weighted_score += (2 * w3)

        # Add the weighted score to the rule dictionary
        rule["weighted_score"] = weighted_score

        total_weighted_score += weighted_score
    #return guideline
    return round(total_weighted_score, 2)

#Extract Violation and count from modsec_audit.log
def parse_rule_violations(log_file):
    rule_violations = {}
    current_violation = None
    
    with open(log_file, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if line.startswith('--'):
                if current_violation is not None:
                    if current_violation not in rule_violations:
                        rule_violations[current_violation] = {"count": 1}
                    else:
                        rule_violations[current_violation]["count"] += 1
                current_violation = None
            elif line.startswith('Message:'):
                if current_violation is not None:
                    current_violation += '\n' + line.strip()
                else:
                    current_violation = line.strip()

    result = "Rule Violations:\n"
    for violation, data in rule_violations.items():
        result += f'{violation}\nCount: {data["count"]}\n\n'

    return result


result = parse_rule_violations("/var/log/apache2/modsec_audit.log")
ruleList = result.split('\n\n')
result = parse_rule_violations("/var/log/apache2/modsec_audit.log")


def explain_regex(regex, id, type):
    #Open the Guideline_regex.json file
    if type == "guideline":
        guideline_regex = open_json("Guideline_regex.json")
    else:
        guideline_regex = open_json("waf_regex.json")
    #Check if guideline contains id
    for i in range(len(guideline_regex)):
        if guideline_regex[i].get("id") == id and guideline_regex[i].get("regex") == regex:
            explanation = guideline_regex[i].get("explanation")
            print("Regex exists. No Call is needed.")
            return explanation

    #Else make call
    url = 'https://api.regexplain.ai/api/v1/explain'
    data = {'regex': regex}
    headers = {'Content-Type':'application/json'}
    response = requests.post(url,json=data,headers=headers)
    explanation = response.text
    try:
        explanation_trim = explanation.index("This") + len("This")
        explanation_trim1 = explanation.index('"}', explanation_trim)
        trimmed_sentece = explanation[explanation_trim: explanation_trim1].strip()
        trimmed_sentece = "This " + trimmed_sentece
    except:
        trimmed_sentece = explanation
    regex_dict = {}
    regex_dict["id"] = id
    regex_dict["regex"] = regex
    regex_dict["explanation"] = trimmed_sentece
    guideline_regex.append(regex_dict)

    if type == "guideline":
        with open("Guideline_regex.json", "w") as f:
            json.dump(guideline_regex, f)
    else:
        with open("waf_regex.json", "w") as f:
            json.dump(guideline_regex, f)
    return trimmed_sentece

# creating data structures to store configurations of ModSecurity
def enableModSecurityDict():
    return {
        "SecRuleEngine": None
    }


def requestBodyDict():
    return {
        "SecRequestBodyAccess": None,
        "SecRequestBodyLimit": None,
        "SecRequestBodyNoFilesLimit": None,
        "SecRequestBodyLimitAction": None,
        "SecRequestBodyJsonDepthLimit": None,
        "SecPcreMatchLimit": None,
        "SecPcreMatchLimitRecursion": None
    }


def responseBodyDict():
    return {
        "SecResponseBodyAccess": None,
        "SecResponseBodyMimeType": None,
        "SecResponseBodyLimit": None,
        "SecResponseBodyLimitAction": None
    }


def uploadDict():
    return {
        "SecUploadDir": None,
        "SecUploadKeepFiles": None,
        "SecUploadFileMode": None
    }


def debugLogDict():
    return {
        "SecDebugLog": None,
        "SecDebugLogLevel": None
    }


def auditLogDict():
    return {
        "SecAuditEngine": None,
        "SecAuditLogRelevantStatus": None,
        "SecAuditLogParts": None,
        "SecAuditLogType": None,
        "SecAuditLog": None,
        "SecAuditLogStorageDir": None
    }


def filesystemConfigDict():
    return {
        "SecTmpDir": None,
        "SecDataDir": None
    }


def miscConfigDict():
    return {
        "SecArgumentSeparator": None,
        "SecCookieFormat": None,
        "SecUnicodeMapFile": None,
        "SecStatusEngine": None
    }

def readConfigFile(filename, dict):
    # convert the config files into dictionaries
    configFile = open(filename, 'r')
    lines = configFile.readlines()
    for line in lines:
        if not line.isspace() and not line.startswith('#'):
            for key in dict:
                lineList = line.split(" ", 1)
                if lineList[0] == key:
                    if len(lineList[1:]) == 1:
                        dict.update({key: lineList[1]})
                    else:
                        dict.update({key: lineList[1:]})

    return dict

# comparing each section of the config
def checkModSecurityEnabled(modSecurityEnabled, pdf):

    secRuleEngine = modSecurityEnabled.get('SecRuleEngine').strip()

    if secRuleEngine == "On":
        explanation = "ModSecurity is enabled and any rules configured will be processed."
        create_table("SecRuleEngine", modSecurityEnabled.get('SecRuleEngine'),
                     "-", explanation, pdf)
    elif secRuleEngine == "DetectionOnly":
        explanation = "ModSecurity is enabled and any rules will be processed, but will not execute any disruptive actions."
        create_table("SecRuleEngine", modSecurityEnabled.get('SecRuleEngine'),
                     "-", explanation, pdf)
    elif secRuleEngine == "Off":
        explanation = "ModSecurity is disabled and no rules will be processed."
        create_table("SecRuleEngine", modSecurityEnabled.get('SecRuleEngine'),
                     "-", explanation, pdf)
    else:
        explanation = "Invalid setting, valid settings are On|Off|DetectionOnly"
        create_table("SecRuleEngine", modSecurityEnabled.get('SecRuleEngine'),
                     "-", explanation, pdf)

    return pdf

def checkRequestBodyConfig(currentRequestConfig, recommendedRequestConfig, pdf):

    if currentRequestConfig.get('SecRequestBodyAccess') == recommendedRequestConfig.get('SecRequestBodyAccess'):
        if currentRequestConfig.get('SecRequestBodyLimit') != recommendedRequestConfig.get('SecRequestBodyLimit'):
            if int(currentRequestConfig.get('SecRequestBodyLimit')) > 1073741824:
                explanation = "ModSecurity will automatically drop any files above 1GB in size, please reduce this number."
                create_table( "SecRequestBodyAccess",currentRequestConfig.get('SecRequestBodyLimit'), recommendedRequestConfig.get('SecRequestBodyAccess'), explanation, pdf)
        if currentRequestConfig.get('SecRequestBodyNoFilesLimit') != recommendedRequestConfig.get('SecRequestBodyNoFilesLimit'):
            if int(currentRequestConfig.get('SecRequestBodyNoFilesLimit')) > 1073741824:
                explanation = "ModSecurity will automatically drop any files above 1GB in size, please reduce this number."
                create_table("SecRequestBodyNoFilesLimit", currentRequestConfig.get('SecRequestBodyNoFilesLimit'), recommendedRequestConfig.get('SecRequestBodyNoFilesLimit'), explanation, pdf)
        if currentRequestConfig.get("SecRequestBodyLimitAction") != recommendedRequestConfig.get("SecRequestBodyLimitAction"):
            explanation = "Setting this option to ProcessPartial may cause a possible evasion issue since only the first part of the request that can fit inside the limit to be inspected."
            create_table(currentRequestConfig.get('SecRequestBodyLimitAction'), recommendedRequestConfig.get('SecRequestBodyLimitAction'), explanation, pdf)
        if currentRequestConfig.get("SecRequestBodyLimitAction", "SecPcreMatchLimit") != recommendedRequestConfig.get("SecPcreMatchLimit"):
            if int(currentRequestConfig.get("SecPcreMatchLimit")) < 10000000:
                explanation = "While ModSecurity sets the default PCRE limit at " + recommendedRequestConfig.get("SecPcreMatchLimit") + " to limit the chance of a regex DoS attack, it comes at a cost of getting the 'Rule execution error - PCRE limits exceeded (-8)' error, which causes a 403 error when accessing the page. Therefore, it is recommended to increase this value to 500000, as per https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/656"
                create_table("SecPcreMatchLimit", currentRequestConfig.get('SecPcreMatchLimit'),
                     recommendedRequestConfig.get('SecPcreMatchLimit'), explanation, pdf)

        if currentRequestConfig.get("SecPcreMatchLimitRecursion") != recommendedRequestConfig.get("SecPcreMatchLimitRecursion"):
                if int(currentRequestConfig.get("SecPcreMatchLimitRecursion")) < 10000000:
                    explanation = "While ModSecurity sets the default PCRE limit at " + recommendedRequestConfig.get("SecPcreMatchLimitRecursion") + " to limit the chance of a regex DoS attack, it comes at a cost of getting the 'Rule execution error - PCRE limits exceeded (-8)' error, which causes a 403 error when accessing the page. Therefore, it is recommended to increase this value to 500000, as per https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/656"
                    create_table("SecPcreMatchLimitRecursion", currentRequestConfig.get('SecPcreMatchLimitRecursion'),
                         recommendedRequestConfig.get('SecPcreMatchLimitRecursion'), explanation, pdf)
    else:
        explanation = "ModSecurity is not able to read request bodies, it is recommended to set this to 'On'."
        create_table("SecRequestBodyAccess", currentRequestConfig.get('SecRequestBodyAccess'),
                     recommendedRequestConfig.get('SecRequestBodyAccess'), explanation, pdf)

    return pdf

def checkResponseBodyConfig(currentResponseConfig, recommendedResponseConfig, pdf):
    if currentResponseConfig.get('SecResponseBodyAccess') == recommendedResponseConfig.get('SecResponseBodyAccess'):
        # print("WARNING: Enabling this would increase latency and memory consumption.")
        if currentResponseConfig.get("SecResponseBodyMimeType") != recommendedResponseConfig.get("SecResponseBodyMimeType"):
            explanation = "The current configuration does not support all recommended MIME types for response body buffering, but if your application does not use the types, then there is no need for action."
            create_table("SecResponseBodyMimeType", currentResponseConfig.get("SecResponseBodyMimeType"), recommendedResponseConfig.get("SecResponseBodyMimeType"), explanation, pdf)
        if currentResponseConfig.get('SecResponseBodyLimit') != recommendedResponseConfig.get('SecResponseBodyLimit'):
            if int(currentResponseConfig.get('SecResponseBodyLimit')) > 1073741824:
                explanation = "ModSecurity will automatically drop any files above 1GB in size, please reduce this number."
                create_table("SecResponseBodyLimit", currentResponseConfig.get("SecResponseBodyLimit"),
                             recommendedResponseConfig.get("SecResponseBodyLimit"), explanation, pdf)
        if currentResponseConfig.get('SecResponseBodyLimitAction') != recommendedResponseConfig.get('SecResponseBodyLimitAction'):
            explanation = "Recommended to be changed to ProcessPartial in case your website has a long response body. It would be less secure, but only in the case where the attack controls the output of the body."
            create_table("SecResponseBodyLimitAction", currentResponseConfig.get("SecResponseBodyLimitAction"),
                         recommendedResponseConfig.get("SecResponseBodyLimitAction"), explanation, pdf)
    else:
        explanation = "It is recommended to enable this to identify errors and data leakage issues."
        create_table("SecResponseBodyAccess", currentResponseConfig.get("SecResponseBodyAccess"),
                     recommendedResponseConfig.get("SecResponseBodyAccess"), explanation, pdf)
    return pdf

def checkUploadConfig(currentUploadConfig, pdf):
    # since the recommended config does not enable this, we will check against the system config
    secUploadDir = currentUploadConfig.get("SecUploadDir")
    if secUploadDir:
        if (os.access(secUploadDir, os.F_OK) == False):
            explanation = "Directory does not exist, it is recommended to create a directory with read and write access to the user ONLY, or this user is not able to view the directory."
            create_table("SecUploadDir", currentUploadConfig.get("SecUploadDir"),
                         "-", explanation, pdf)
        if (oct(os.stat(secUploadDir).st_mode)[5:6] != "6"):
            explanation = "Directory does not have the appropriate permissions, please check if the directory has READ and WRITE permissions."
            create_table("SecUploadDir", currentUploadConfig.get("SecUploadDir"),
                         "-", explanation, pdf)
        if (oct(os.stat(secUploadDir).st_mode)[6:8] != "00"):
            explanation = "Directory has permissions that allow others besides the user to access the directory. It is recommended to allow read and write access to the user only."
            create_table("SecUploadDir", currentUploadConfig.get("SecUploadDir"),
                         "-", explanation, pdf)
        if currentUploadConfig.get("SecUploadKeepFiles") != "RelevantOnly":
            explanation = "It is recommended for files relevant to the request to be kept to save space."
            create_table("SecUploadKeepFiles", currentUploadConfig.get("SecUploadKeepFiles"),
                         "RelevantOnly", explanation, pdf)
        if currentUploadConfig.get("SecUploadFileMode") != "0600":
            explanation = "It is recommended for the files saved to only have read and write permissions for the owner only."
            create_table("SecUploadFileMode", currentUploadConfig.get("SecUploadFileMode"),
                         "0600", explanation, pdf)
    else:
        explanation = "Recommended to enable this unless your web application does not allow file uploads at all."
        create_table("SecUploadDir", "Disabled",
                     "-", explanation, pdf)

    return pdf

def checkDebugConfig(currentDebugConfig, pdf):
    secDebugLog = currentDebugConfig.get("SecDebugLog")
    if secDebugLog:
        if (os.access(secDebugLog, os.F_OK) == False):
            explanation = secDebugLog + " does not exist, it is recommended to create a file with read and write access to the user ONLY, or this user is not able to view the directory."
            create_table("SecDebugLog", secDebugLog,
                         "-", explanation, pdf)
        if (oct(os.stat(secDebugLog).st_mode)[5:6] != "6"):
            explanation = secDebugLog + " does not have the appropriate permissions, please check if the file has READ and WRITE permissions."
            create_table("SecDebugLog", secDebugLog,
                         "-", explanation, pdf)
        if (oct(os.stat(secDebugLog).st_mode)[6:8] != "00"):
            explanation = secDebugLog + " has permissions that allow others besides the user to access the file. It is recommended to allow read and write access to the user only."
            create_table("SecDebugLog", secDebugLog,
                         "-", explanation, pdf)
        if currentDebugConfig.get("SecDebugLogLevel") > 3:
            explanation = "In a production environment, it is recommended to 3 if you really need logging, but 0 is optimal performance-wise."
            create_table("SecUploadFileMode", currentDebugConfig.get("SecDebugLogLevel"),
                         "3 or lesser", explanation, pdf)
    else:
        explanation = "When testing, debug should be enabled to facilitate troubleshooting process. In production, debug should be disabled, or set to 3 at maximum."
        create_table("SecDebugLog", "Disabled",
                     "-", explanation, pdf)

    return pdf

def checkAuditConfig(currentAuditConfig, recommendedAuditConfig, pdf):
    if currentAuditConfig.get("SecAuditEngine") == recommendedAuditConfig.get("SecAuditEngine"):
        if currentAuditConfig.get("SecAuditLogRelevantStatus") != recommendedAuditConfig.get("SecAuditLogRelevantStatus"):
            explanation = "It is recommended to follow the regex as specified, as it logs all 5xx and 4xx status codes, except for 404."
            create_table("SecAuditLogRelevantStatus", currentAuditConfig.get("SecAuditLogRelevantStatus"),
                         recommendedAuditConfig.get("SecAuditLogRelevantStatus"), explanation, pdf)

        if sorted(currentAuditConfig.get("SecAuditLogParts")) != sorted(recommendedAuditConfig.get("SecAuditLogParts")):
            if "A" and "Z" in currentAuditConfig.get("SecAuditLogParts"):
                explanation = "Mandatory fields are present, but the config does not follow the recommended config."
            else:
                explanation = "Mandatory fields A and Z are missing."
            create_table("SecAuditLogParts", currentAuditConfig.get("SecAuditLogParts"),
                         recommendedAuditConfig.get("SecAuditLogParts"), explanation, pdf)
        if currentAuditConfig.get("SecAuditLogType") == "Serial":
            if currentAuditConfig.get("SecAuditLog"):
                secAuditLog = currentAuditConfig.get("SecAuditLog")
                if (os.access(secAuditLog, os.F_OK) == False):
                    explanation = secAuditLog + " does not exist, it is recommended to create a file with read and write access to the user ONLY, or this user is not able to view the directory."
                    create_table("SecAuditLog", currentAuditConfig.get("SecAuditLog"),
                                 "-", explanation, pdf)
                if (oct(os.stat(secAuditLog).st_mode)[5:6] != "6"):
                    explanation = secAuditLog + " does not have the appropriate permissions, please check if the file has READ and WRITE permissions."
                    create_table("SecAuditLog", oct(os.stat(secAuditLog).st_mode)[5:6],
                                 "6", explanation, pdf)
                if (oct(os.stat(secAuditLog).st_mode)[6:8] != "00"):
                    explanation = secAuditLog + " has permissions that allow others besides the user to access the file. It is recommended to allow read and write access to the user only."
                    create_table("SecAuditLog", oct(os.stat(secAuditLog).st_mode)[6:8],
                                 "00", explanation, pdf)
            else:
                explanation = "No audit log file specified."
                create_table("SecAuditLog", currentAuditConfig.get("SecAuditLog"),
                             recommendedAuditConfig.get("SecAuditLog"), explanation, pdf)
        if currentAuditConfig.get("SecAuditLog") == "Concurrent":
            if currentAuditConfig.get("SecAuditLogStorageDir"):
                secAuditLogDir = currentAuditConfig.get("SecAuditLogStorageDir")
                if (os.access(secAuditLogDir, os.F_OK) == False):
                    explanation = "Directory does not exist, it is recommended to create a directory with read and write access to the user ONLY, or this user is not able to view the directory."
                    create_table("SecAuditLogStorageDir", currentAuditConfig.get("SecAuditLogStorageDir"),
                                 "-", explanation, pdf)
                if (oct(os.stat(secAuditLogDir).st_mode)[5:6] != "6"):
                    explanation = "Directory does not have the appropriate permissions, please check if the directory has READ and WRITE permissions."
                    create_table("secAuditLogDir", oct(os.stat(secAuditLogDir).st_mode)[5:6],
                                 "6", explanation, pdf)
                if (oct(os.stat(secAuditLogDir).st_mode)[6:8] != "00"):
                    explanation = "Directory has permissions that allow others besides the user to access the directory. It is recommended to allow read and write access to the user only."
                    create_table("secAuditLogDir", oct(os.stat(secAuditLogDir).st_mode)[6:8],
                                 "00", explanation, pdf)
        if currentAuditConfig.get("SecAuditLogType") != "Concurrent" or "Serial":
            explanation = "Unsupported audit log type"
            create_table("SecAuditLogType", currentAuditConfig.get("SecAuditLogType"),
                         "Serial or Concurrent", explanation, pdf)

    else:
        explanation = "It is recommended to set this to RelevantOnly, to log transactions that result in errors."
        create_table("SecAuditEngine", currentAuditConfig.get("SecAuditEngine"),
                     recommendedAuditConfig.get("SecAuditEngine"), explanation, pdf)
    return pdf

def checkFilesystemConfig(currentFilesystemConfig, recommendedFilesystemConfig, pdf):

    # This assumes that the user who runs this code is logged onto is root

    currentSecTmpDir = currentFilesystemConfig.get('SecTmpDir')
    recommendedSecTmpDir = recommendedFilesystemConfig.get('SecTmpDir')

    currentSecDataDir = currentFilesystemConfig.get('SecDataDir')
    recommendedSecDataDir = recommendedFilesystemConfig.get('SecDataDir')
    if currentSecTmpDir == recommendedSecTmpDir:
        explanation = "Although the default directory to store temporary files is /tmp, it is recommended to change to specify a location that's private."
        create_table("SecTmpDir", currentSecTmpDir,
                     recommendedSecTmpDir, explanation, pdf)
    else:
        if (os.access(currentSecTmpDir, os.F_OK) == False):
            explanation = currentSecTmpDir + " does not exist, it is recommended to create a directory with read and write access to the user ONLY, or this user is not able to view the directory."
            create_table("SecTmpDir", currentSecTmpDir,
                         recommendedSecTmpDir, explanation, pdf)
        if (oct(os.stat(currentSecTmpDir).st_mode)[5:6] != "6"):
            explanation = currentSecTmpDir + " does not have the appropriate permissions, please check if the directory has READ and WRITE permissions."
            create_table("SecTmpDir", oct(os.stat(currentSecTmpDir).st_mode)[5:6],
                         "6", explanation, pdf)
        if (oct(os.stat(currentSecTmpDir).st_mode)[6:8] != "00"):
            explanation = currentSecTmpDir + " has permissions that allow others besides the user to access the directory. It is recommended to allow read and write access to the user only."
            create_table("SecTmpDir", oct(os.stat(currentSecTmpDir).st_mode)[6:8],
                         "00", explanation, pdf)

    if currentSecDataDir == recommendedSecDataDir:
        explanation = "Although the default directory to store persistent data is /tmp, it is recommended to change to specify a location that's private."
        create_table("SecTmpDir", currentSecDataDir,
                     recommendedSecDataDir, explanation, pdf)
    else:
        if (os.access(currentSecTmpDir, os.F_OK) == False):
            explanation = currentSecDataDir + " does not exist, it is recommended to create a directory with read and write access to the user ONLY, or this user is not able to view the directory."
            create_table("SecTmpDir", currentSecDataDir,
                         currentSecDataDir, explanation, pdf)
        if (oct(os.stat(currentSecTmpDir).st_mode)[5:6] != "6"):
            explanation = currentSecDataDir + " does not have the appropriate permissions, please check if the directory has READ and WRITE permissions."
            create_table("SecDataDir", oct(os.stat(currentSecTmpDir).st_mode)[5:6],
                         "6", explanation, pdf)
        if (oct(os.stat(currentSecTmpDir).st_mode)[6:8] != "00"):
            explanation = currentSecDataDir + " has permissions that allow others besides the user to access the directory. It is recommended to allow read and write access to the user only."
            create_table("SecDataDir", oct(os.stat(currentSecTmpDir).st_mode)[6:8],
                         "00", explanation, pdf)

    return pdf

def checkMiscConfig(currentMiscConfig, recommendedMiscConfig, pdf):
    if currentMiscConfig.get("SecArgumentSeparator") != recommendedMiscConfig.get("SecArgumentSeparator"):
        explanation = "Unless the web application is using a non-standard separator, it should be set as '&'."
        create_table("SecArgumentSeparator", currentMiscConfig.get("SecArgumentSeparator"),
                     recommendedMiscConfig.get("SecArgumentSeparator"), explanation, pdf)
    if currentMiscConfig.get("SecCookieFormat") != recommendedMiscConfig.get("SecCookieFormat"):
        explanation = "Unless the web application is using version 1 Cookies, it should be set as 0 (netscape cookies)."
        create_table("SecCookieFormat", currentMiscConfig.get("SecCookieFormat"),
                     recommendedMiscConfig.get("SecCookieFormat"), explanation, pdf)
    if currentMiscConfig.get("SecUnicodeMapFile") != recommendedMiscConfig.get("SecUnicodeMapFile"):
        explanation = "Better to follow the recommended config, unless you have a different unicode file to use."
        create_table("SecUnicodeMapFile", currentMiscConfig.get("SecUnicodeMapFile"),
                     recommendedMiscConfig.get("SecUnicodeMapFile"), explanation, pdf)
    if currentMiscConfig.get("SecStatusEngine") != recommendedMiscConfig.get("SecStatusEngine"):
        explanation = "Recommended to set to Off; as of 2022, there is no receiver for this information."
        create_table("SecStatusEngine", currentMiscConfig.get("SecStatusEngine"),
                     recommendedMiscConfig.get("SecStatusEngine"), explanation, pdf)

    return pdf


def create_arrray(w, x, y, z=None):
    array = []
    array.append(w)
    array.append(x)
    array.append(y)
    if z is None:
        array.append(None)
    if z is not None:
        array.append(z)
    return array

rules_with_differences = []

guideline = open_json("Guideline.json")
#waf = open_json("waf.json")
waf = open_json("waf.json")

#Number of rules in the guideline
size1 = len(guideline)
#Number of rules on the web
size2 = len(waf)
#Var count stores the number of rules that is in the guideline but not in the WAF
count = 0
for i in range(size1):
    index = return_Index(i)
    if index == -1:
        count += 1
        
pie_chart(count, size1, "Not in WAF", "In WAF", "Percentage of rules in guidelines but not in waf")

#Number of rules in the guideline that is in the WAF
count1 = size1 - count
#Number of rules in the WAF that is not part of CRS
count = size2 - count1
pie_chart(count, size2, "Not in CRS", "In CRS", "Rules deployed on WAF")

#Compare the version of each rule found in the Guideline with those found in the WAF
version = get_latest_tag(guidelineURL)
version = version[1:-4].strip()
print("Audit in progress...Please do not close this terminal")
is_latest_version = None
rules1 = []
for i in range(size1):
    index = return_Index(i)
    #Rule is CRS
    if index != -1:
        version_string = waf[index].get("ver")
        try:
            version_string_split = version_string.split('/')
            if len(version_string_split) >= 2:
                version_number = version_string_split[1]
                #If guideline version is newer than rule version
                if LooseVersion(version_number) < LooseVersion(version):
                    is_latest_version = False
                    #Get Rule ID
                    id = waf[index].get("id")
                    rule = create_arrray(id, version_number, version)
                    rules1.append(rule)
                    rules_with_differences.append(waf[index].get("id"))
        except:
            pass

total_score = calculate_weighted_scores("Guideline.json")
waf_score = calculate_weighted_scores("waf.json")
result = parse_rule_violations("/var/log/apache2/modsec_audit.log")

severitys = []
is_severity_same = None
for i in range(size1):
    index = return_Index(i)
    if index != -1:
        Guideline_severity = guideline[i].get("severity")
        WAF_severity = waf[index].get("severity")
        if Guideline_severity != WAF_severity:
            is_severity_same = False
            severity = create_arrray(waf[index].get("id"), WAF_severity, Guideline_severity)
            severitys.append(severity)
            rules_with_differences.append(waf[index].get("id"))

actions = []
is_action_same = None
for i in range(size1):
    index = return_Index(i)
    if index != -1:
        if guideline[i].get("id") == waf[index].get("id"):
            guideline_keys = guideline[i].keys()
            waf_keys = waf[index].keys()
            guideline_action = ""
            waf_action = ""
            if 'pass' in guideline_keys:
                guideline_action = 'pass'
            elif 'block' in guideline_keys:
                guideline_action = 'block'
            elif 'deny' in guideline_keys:
                guideline_action = 'deny'
            if 'pass' in waf_keys:
                waf_action = 'pass'
            elif 'block' in waf_keys:
                waf_action = 'block'
            elif 'deny' in waf_keys:
                waf_action = 'deny'
            if guideline_action != waf_action:
                is_action_same = False
                id1 = guideline[i].get("id")
                action = create_arrray(waf[index].get("id"), waf_action, guideline_action)
                actions.append(action)
                rules_with_differences.append(waf[index].get("id"))

request_headers = []
is_request_header_same = None
explanation = ""
for i in range(size1):
    index = return_Index(i)
    if index != -1:
        waf_key = 0
        waf_value = 0
        guideline_key = 0
        guideline_value = 0
        for key,value in waf[index].items():
            if "Sec" in key and "TX" not in key:
                waf_key = key
                waf_value = value
                break
        for key,value in guideline[i].items():
            if "Sec" in key and "TX" not in key:
                guideline_key = key
                guideline_value = value
                break
        if guideline_key != waf_key or guideline_value != waf_value:
            header = guideline_key + guideline_value
            header1 = waf_key + waf_value
            explanation = explain_regex(header, guideline[i].get("id"), "guideline")
            explanation1 = explain_regex(header1, waf[index].get("id"), "waf")
            is_request_header_same = False
            request_header = create_arrray(guideline[i].get("id"), header, header1, guideline[i].get("msg"))
            request_header.append(explanation.replace("\n\n", " "))
            request_header.append(explanation1.replace("\n\n", " "))
            request_headers.append(request_header)
            rules_with_differences.append(waf[index].get("id"))

unique_sorted_array = sorted(set(rules_with_differences))
pie_chart(len(unique_sorted_array), count1, "With difference", "No difference", "Rules deployed on WAF")


        

#---------------------------------Prepping PDF-------------------------------
def section_header(section_name):
    pdf.set_font('Arial', 'B', 15)
    pdf.cell(0, 20, section_name, 'B', 1, '')

def section_text(section_text):
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 7, section_text, 0, 1, '')

def table_3_by_3(col1, col2, col3, data_array):
    pdf.set_font('Arial', 'B', 12)
    col_width = pdf.w / 3.3
    row_height = pdf.font_size * 2
    #Create the table headers
    pdf.cell(col_width, row_height, col1, border=1, align='C')
    pdf.cell(col_width, row_height, col2, border=1, align='C')
    pdf.cell(col_width, row_height, col3, border=1, align='C')
    pdf.ln()
    pdf.set_font('Arial', '', 12)
    #Create the table rows
    for i in range(len(data_array)):
        pdf.cell(col_width, row_height, str(data_array[i][0]), border=1, align='C')
        pdf.cell(col_width, row_height, str(data_array[i][1]), border=1, align='C')
        pdf.cell(col_width, row_height, str(data_array[i][2]), border=1, align='C')
        pdf.ln()

def table_2_by_2(data_array):
    pdf.set_font('Arial', 'B', 12)
    col_width = pdf.w / 1.1
    row_height = pdf.font_size * 2
    for i in range(len(data_array)):
        pdf.cell(col_width, row_height, data_array[i][0], border=1, align='')
        pdf.ln()
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(col_width, row_height, str(data_array[i][1]), border=1, align='')
        pdf.set_font('Arial', 'B', 12)

def table_variable(row_heading, data):
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(col_width, row_height, row_heading, border=1, align='')
    pdf.ln()
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(col_width, row_height, data, border=1, align='')

def create_table(config, currentConfig, recommendedConfig, explanation, pdf):
    # used for comparing config
    pdf.set_font("Arial", "B", size=12)

    col_width = pdf.w / 1.1
    row_height = pdf.font_size * 2

    config = "Configuration: " + config

    pdf.cell(col_width, row_height, config, border=1, align='C')
    pdf.ln()
    table_variable("Current", currentConfig)
    table_variable("Recommended", recommendedConfig)
    table_variable("Explanation", explanation)
    return pdf

pdf = FPDF()
pdf.add_page()
pdf.set_font('Arial', 'B', 30)
pdf.cell(0, 20, 'Gods Web', 0, 1, 'C')

pdf.set_font('Arial', '', 10)
description = 'Generated on: ' + str(datetime.now())
pdf.multi_cell(0, 7, description, 0, 1, '')
section_header("Overview")
section_text("This report presents the results of God's Web, which is designed to evaluate the configuration of an OWASP Web Application Firewall (WAF) against the OWASP Core Rule Set (CRS) best practices. The tool assesses whether each CRS rule is present in the WAF configuration and ensures that the security levels of each rule cannot be lower than the CRS guidelines. The results of the audit tool are presented in the following sections, providing key findings and recommendations for improving the WAF configuration to align with CRS best practices.")

section_header("Compliance")
section_text("Of the " + str(size1) + " rules in the guideline, only " + str(count1) + " of them are deployed on the WAF. The following pie chart shows the distribution of WAF rules that are included in the guideline but are not present in the WAF, expressed as a percentage of the total number of WAF rules.")
pdf.image('pie_chart.png', 30, 155, w = 140, h = 120, type = '', link = '')
pdf.add_page()
section_text("Of the " + str(count1) + " rules deplyed on the WAF, " + str(len(unique_sorted_array)) + " of them have different configurations from the guideline. The following pie chart shows the distribution of WAF rules that are found to be different, expressed as a percentage of the total number of WAF rules.")
pdf.image('pie_chart_2.png', 30, 30, w = 140, h = 120, type = '', link = '')

pdf.add_page()
section_header("WAF Breakdown")
section_text("Of the " + str(size2) + " rules on the WAF, only " + str(count1) +  " of them are included in the ModSecurity Core Rule Set (CRS). The following pie chart shows the distribution of WAF rules that are included in the ModSecurity Core Rule Set (CRS) and custom rules, expressed as a percentage of the total number of WAF rules.")
pdf.image('pie_chart_1.png', 30, 70, w = 140, h = 120, type = '', link = '')
pdf.set_y(160)
col_width = pdf.w / 1.1
row_height = pdf.font_size * 2

pdf.add_page()
section_header("Rule Variables")
if is_request_header_same is False:
    section_text("Variables in ModSecurity rule are used to define conditions that trigger specific actions, such as blocking or logging a request")
    pdf.ln()
    section_text("If ModSecurity variables are set incorrectly, it can lead to unexpected behavior or errors in the rules processing. This can result in the rules not functioning as intended, or potentially blocking legitimate traffic.\n\nThe following rules have different variables configured: ")
    #col_width = pdf.w / 1.1
    #row_height = pdf.font_size * 2
    for i in range(len(request_headers)):
        pdf.set_font('Arial', 'B', 12)
        message = "Rule ID:" + str(request_headers[i][0])
        pdf.cell(col_width, row_height, message, border=1, align='C')
        pdf.ln()
        table_variable("Description", str(request_headers[i][3]))
        text_latin1 = unicodedata.normalize('NFKD', str(request_headers[i][1])).encode('latin-1', 'ignore').decode('latin-1')
        text_latin2 = unicodedata.normalize('NFKD', str(request_headers[i][2])).encode('latin-1', 'ignore').decode('latin-1')
        table_variable("Configured Variable", text_latin2)
        table_variable("Configured Regex Explanation", str(request_headers[i][5]))
        table_variable("Recommended Variable", text_latin1)
        table_variable("Recommended Regex Explanation", str(request_headers[i][4]))
        pdf.ln()
else:
    section_text('All rules have the same header')
    section_text("Your WAF has the recommended rule variables set as per the guideline. Your WAF is more likely to identify and respond to specific conditions that may indicate an attack. Your WAF is better equipped to handle a wide range of security threats, with a reduced risk of false positives or false negatives.")

section_header("Version")
if is_latest_version is False:
    section_text('As of ' + str(datetime.now()) + ', the latest version of ModSecurity Core Rule Set (CRS) is: ' + version + '. The following rules are not using the latest version. Please check the latest version from https://github.com/coreruleset/coreruleset')
    pdf.ln()
    table_3_by_3("Rule ID", "Current Version", "Latest Version", rules1)
else:
    section_text('As of ' + str(datetime.now()) + ', the latest version of ModSecurity Core Rule Set (CRS) is: ' + version + '. All rules are currently using the latest version.')
    section_text("Your WAF is the same version as the guideline. It means that the WAF is properly configured and aligned with the best practices recommended by the OWASP CRS guideline. Keeping the version of the WAF rule set up to date with the recommended guideline is important because it helps ensure that the WAF is always up-to-date with the latest security threats and that the configuration remains aligned with best practices.")

pdf.add_page()
section_header("Severity")
if is_severity_same is False:
    section_text("The severity level of a rule in ModSecurity CRS affects the score that is assigned to a particular event or anomaly detected by that rule. Each severity level has a different weight or impact on the overall score that is calculated for a particular request.\n\n The severity levels are as follows:")
    action1 = [['CRITICAL (level 5)','Indicates that the anomaly detected by the rule is very severe and requires immediate attention. A request that triggers such a rule would be assigned a high score, which would indicate that it is likely an attack'], ['ERROR (Level 4)', 'Indicates that the anomaly is serious and could result in a security breach if not addressed. A request that triggers such a rule would be assigned a high score, which would indicate that it is potentially malicious.'], ['WARNING (Level 3)', 'Indicates that the anomaly is of moderate severity and could potentially lead to a security issue. A request that triggers such a rule would be assigned a lower score than a critical or error-level rule.'], ['NOTICE (Level 2)', 'Indicates that the anomaly is of low severity and may not necessarily indicate an attack or security issue. A request that triggers such a rule would be assigned a low score.']]
    table_2_by_2(action1)
    pdf.ln()
    section_text("It is important to configure the WAF rules based on the severity of the application's security needs. If the configured WAF rules have a lower severity than the OWASP CRS Guideline rules, it may result in a higher risk of successful attacks. \n\nThe following rules have different severity")
    table_3_by_3("Rule ID", "Configured Severity", "Recommended Severity", severitys)
else:
    section_text('All rules are currently using the latest version')
    section_text("Your WAF has followed the guideline perfectly for the Severity of each rule. By following the severity guidelines in a WAF, the WAF can distinguish between more severe and less severe anomalies and assign scores accordingly. This can help prioritise which events require immediate attention and which ones can be investigated later. Maintaining this standard is also important because as new threats emerge, the severity of rules may need to be adjusted accordingly. It is essential to periodically review and update the severity levels to ensure that the WAF is providing the appropriate level of protection.")
pdf.add_page()
section_header("Action")
if is_action_same is False:
    section_text('In ModSecurity, "pass", "deny", and "block" are actions that can be taken by a rule when a request or response matches that rule.\n\nThe various actions are as follows:')
    action1 = [['pass', 'Rule will be skipped and the request/response will be allowed to continue through the WAF without being blocked or flagged as an anomaly.'], ['deny', 'Request will be blocked, and the client will receive a response indicating that their request was denied.'], ['block', 'similar to "deny" in that it also blocks the request, but it also generates an event that can be logged and alerts the WAF administrator to the attempted attack.']]
    table_2_by_2(action1)
    pdf.ln()
    section_text('These actions are usually associated with the severity level of a rule, with higher severity rules being more likely to "deny" or "block" a request. The specific actions taken by a rule depend on the configuration of the WAF, including the desired level of protection, the sensitivity of the protected application, and the likelihood of false positives.\nHaving current configured rules to have lower restrictive actions such as "pass" when it should be a higher restrictive action such as "deny" can leave the system vulnerable to attacks.\n\nThe following rules have different actions:')
    table_3_by_3("Rule ID", "Configured Action", "Recommended Action", actions)
else:
    section_text('All rules are currently using the latest version')
    section_text("Your WAF has followed the guideline perfectly for the Action of each rule. The WAF is providing the desired level of protection while minimising the impact on legitimate traffic by having the recommended action for its SecRules. It is important to regularly review and maintain this standard for continued protection.")

pdf.add_page()
section_header("Scoring")
section_text('The OWASP CRS anomaly scoring system is derived by combining two factors: severity and paranoia level, with severity carrying a higher weight than paranoia level.\n\n')
action1 = [['Severity', 'Is determined by the type of attack and the potential impact it could have on the system.'], ['Paranoia', 'Reflects the likelihood that the rule could generate false positives or block legitimate traffic.']]
table_2_by_2(action1)
pdf.ln()
section_text("The aim should be to achieve a score as close as possible to the score of the OWASP CRS Guideline. This indicates that the WAF configuration is aligned with the best practices outlined in the guideline.\nHowever, having a higher severity or paranoia level does not necessarily mean a rule is more secure. It means that the rule is more likely to detect and potentially block an attack that matches the rule's criteria. A rule with a high anomaly score is more likely to detect more sophisticated attacks, but it also increases the risk of false positives.\nIt is important to note that the anomaly scoring is just one aspect of WAF configuration management. Other factors such as the accuracy of the rules, false positives, and false negatives should also be considered in determining the effectiveness of the WAF. Please consider these factors with your organization's security objectives")
pdf.ln()
section_text('Obtained Score: ' + str(waf_score) + ' / ' + str(total_score))
if waf_score >= total_score * 0.95 and waf_score <= total_score * 1.05:
    section_text("Your average weighted score is near or equals to the guideline. Please continue to perform regular audits to maintain the best practices as per the guideline.")
elif waf_score > total_score:
    section_text("Your average weighted score exceeds the guideline by a significant amount. This suggests that your WAF may be too aggressive in blocking traffic. You may experience higher detection of false positives, where legitimate traffic is blocked or denied. You can adjust the WAF configuration to lower the overall weighted score and bring it closer to the guideline. This can be done by tuning the paranoia level and severity of the rules in the WAF configuration. You can also review the rules in the WAF that are not in the guideline and disable them if they are not needed.")
else:
    section_text("Your average weighted score is lower than guideline by a significant amount. This suggests that your WAF may not be following the security posture recommended by the guideline and is not adequately protecting the web application against attacks. It is important to investigate the reasons for the low weighted score and take appropriate actions to improve the security of the web application. This may involve reviewing and updating the WAF rule sets according to the severity and paranoia levels stated in the guideline.")

pdf.add_page()
section_header("Rule Violations")
section_text('This section outlines the rule violations detected by the WAF. In ModSecurity, rule violations are incidents when a request matches a defined rule or set of rules that are designed to detect and prevent malicious activity. When a rule is triggered, it generates a log entry in the ModSecurity audit log file, which contains information about the request, the rule that was triggered, and other relevant details. To view more information, please refer to the ModSecurity audit log file at /var/log/apache2/modsec_audit.log')  
pdf.ln()
section_text('It is important to keep track of rule violations in ModSecurity audit logs because it can help to detect and prevent potential security threats to your web application. By reviewing the log entries, you can identify patterns of suspicious activity or attacks and take appropriate measures to protect your application from those threats.')
pdf.ln()
section_text('These are the violations found, shown with the rules triggered and number of hits.')
for i in range(len(ruleList)):
    pdf.multi_cell(col_width, row_height, str(ruleList[i]), border=1, align='')
    pdf.ln()

# pull from git
url = "https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended"
recommendedFile = "recommended-config.txt"
response = requests.get(url)
with open(recommendedFile, "wb") as f:
    f.write(response.content)

configFile = '/etc/modsecurity/modsecurity.conf'

pdf.add_page()
section_header("Overview of ModSecurity Configuration")
section_text("This part describes the current configurations against the recommended configurations for ModSecurity.")
pdf.ln()
section_text("Although ModSecurity's recommended configuration does not account for the exact use cases for every implementation, it serves as a recommendation for administrators to follow. "
             "Some configurations have been referenced from other sources due to the limitations of the recommended configuration.")
section_text("This section of the report will only display the non-compliant configurations against the recommended configurations as stated by ModSecurity.")
pdf.ln()


# initializing all parts of the config file
modSecurityEnabled = readConfigFile(configFile, enableModSecurityDict())

currentRequestConfig = readConfigFile(configFile, requestBodyDict())
recommendedRequestConfig = readConfigFile(recommendedFile, requestBodyDict())

currentResponseConfig = readConfigFile(configFile, responseBodyDict())
recommendedResponseConfig = readConfigFile(recommendedFile, responseBodyDict())

currentUploadConfig = readConfigFile(configFile, uploadDict())
recommendedUploadConfig = readConfigFile(recommendedFile, uploadDict())

currentDebugConfig = readConfigFile(configFile, debugLogDict())
recommendedDebugConfig = readConfigFile(recommendedFile, debugLogDict())

currentAuditConfig = readConfigFile(configFile, auditLogDict())
recommendedAuditConfig = readConfigFile(recommendedFile, auditLogDict())

currentFilesystemConfig = readConfigFile(configFile, filesystemConfigDict())
recommendedFilesystemConfig = readConfigFile(recommendedFile, filesystemConfigDict())

currentMiscConfig = readConfigFile(configFile, miscConfigDict())
recommendedMiscConfig = readConfigFile(recommendedFile, miscConfigDict())

pdf = checkModSecurityEnabled(modSecurityEnabled, pdf)
pdf.ln()

# finding the difference between the 2 dicts
# value = {k: currentConfig[k] for k, _ in set(currentConfig.items()) - set(recommendedConfig.items())}
# print(value)
if {k: currentRequestConfig[k] for k, _ in set(currentRequestConfig.items()) - set(recommendedRequestConfig.items())}:
    section_header("Request Configurations")
    pdf = checkRequestBodyConfig(currentRequestConfig, recommendedRequestConfig, pdf)
    pdf.ln()

if {k: currentResponseConfig[k] for k, _ in set(currentResponseConfig.items()) - set(recommendedResponseConfig.items())}:
    section_header("Response Configurations")
    pdf = checkResponseBodyConfig(currentResponseConfig, recommendedResponseConfig, pdf)
    pdf.ln()

if {k: currentFilesystemConfig[k] for k, _ in set(currentFilesystemConfig.items()) - set(recommendedFilesystemConfig.items())}:
    section_header("Filesystem Configurations")
    pdf = checkFilesystemConfig(currentFilesystemConfig, recommendedFilesystemConfig, pdf)
    pdf.ln()

section_header("Upload Configurations")
pdf = checkUploadConfig(currentUploadConfig, pdf)
pdf.ln()

section_header("Debug Configurations")
pdf = checkDebugConfig(currentDebugConfig, pdf)
pdf.ln()

if {k: currentAuditConfig[k] for k, _ in set(currentAuditConfig.items()) - set(recommendedAuditConfig.items())}:
    section_header("Audit Configurations")
    pdf = checkAuditConfig(currentAuditConfig, recommendedAuditConfig, pdf)
    pdf.ln()

if {k: currentMiscConfig[k] for k, _ in set(currentMiscConfig.items()) - set(recommendedMiscConfig.items())}:
    section_header("Miscellaneous Configurations")
    checkMiscConfig(currentMiscConfig, recommendedMiscConfig, pdf)
    pdf.ln()

os.remove(recommendedFile)

#pdf.output(str(datetime.now()) + '.pdf', 'F')
pdf.output('test.pdf', 'F')
print("Your report has been generated")
