import json
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
def return_Index():
    index = -1
    ruleID = guideline[i].get("id")
    for j, obj in enumerate(waf):
        if obj.get("id") == ruleID:
            index = j
            break
    return index

#Generate Pie Chart: x = part of total, y = total
def pie_chart(x, y, xlabel, ylabel, title1):
    #clear the previous plot
    plt.clf()
    # Calculate the proportion of variable1 and variable2
    proportions = [x, y - x]
    # Define the labels for the pie chart
    labels = [xlabel, ylabel]
    # Define the colors for the pie chart
    colors = ['#ff9999','#66b3ff']
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
    #plt.savefig('pie_chart.png')
    
#Calculate Score --> x = WAF / Guideline
def calculate_score(x):
    total_score = 0
    for rule in x:
        anomaly_score, severity = extract_score(rule)
        # Skip over rules without anomaly score and severity
        if anomaly_score is None and severity is None:
            continue
        # Assign score according to anomaly score and severity
        score = 0
        if anomaly_score is not None:
            score += anomaly_score
        if severity == "CRITICAL":
            score += 5
        elif severity == "ERROR":
            score += 4
        elif severity == "WARNING":
            score += 3
        elif severity == "NOTICE":
            score += 2
        total_score += score
        # Add the score to the rule dictionary
        rule["score"] = score
    #print(json.dumps(guideline, indent=4))
    return total_score

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



guideline = open_json("Guideline.json")
waf = open_json("waf.json")
#waf = open_json("Guideline.json")

#Number of rules in the guideline
size1 = len(guideline)
#Number of rules on the web
size2 = len(waf)

#Var count stores the number of rules that is in the guideline but not in the WAF
count = 0
for i in range(size1):
    index = return_Index()
    if index == -1:
        count += 1
        
#pie_chart(count, size1, "Not in WAF", "In WAF", "Percentage of rules in guidelines but not in waf")

#Number of rules in the guideline that is in the WAF
count1 = size1 - count
#Number of rules in the WAF that is not part of CRS
count = size2 - count1
#pie_chart(count, size2, "Not in CRS", "In CRS", "Rules deployed on WAF")

#Compare the version of each rule found in the Guideline with those found in the WAF
version = "4.0.0"
is_latest_version = None
rules1 = []
for i in range(size1):
    index = return_Index()
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
        except:
            pass
#Count the number of rules related to Top 5 web attacks
attacks = {"XSS": 0, "SQL": 0, "Path Traversal": 0, "File Inclusion": 0, "DDoS": 0, "Others": 0}
for rules in waf:
    if "xss" in str(rules.values()).lower():
        attacks["XSS"] += 1
    elif "sql" in str(rules.values()).lower():
        attacks["SQL"] += 1
    elif "path traversal" in str(rules.values()).lower():
        attacks["Path Traversal"] += 1
    elif "file inclusion" in str(rules.values()).lower():
        attacks["File Inclusion"] += 1
    elif "dos" in str(rules.values()).lower():
        attacks["DDoS"] += 1
    else:
        attacks["Others"] += 1

plt.clf()
proportions = np.array(list(attacks.values()))
labels = np.array(list(attacks.keys()))
colors = ['red','orange','yellow','green','blue','violet']
plt.bar(labels, proportions, color=colors)
# Set the tick positions and labels
plt.xticks(np.arange(len(labels)), labels)
# Adjust the spacing of the labels
plt.gcf().autofmt_xdate(rotation=45)
plt.savefig("Bargraph1.png")
total_score = calculate_score(guideline)
waf_score = calculate_score(waf)

severitys = []
is_severity_same = None
for i in range(size1):
    index = return_Index()
    if index != -1:
        Guideline_severity = guideline[i].get("severity")
        WAF_severity = waf[index].get("severity")
        if Guideline_severity != WAF_severity:
            is_severity_same = False
            severity = create_arrray(waf[index].get("id"), WAF_severity, Guideline_severity)
            severitys.append(severity)

actions = []
is_action_same = None
for i in range(size1):
    index = return_Index()
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

request_headers = []
is_request_header_same = None
for i in range(size1):
    index = return_Index()
    if index != -1:
        waf_key = 0
        waf_value = 0
        guideline_key = 0
        guideline_value = 0
        for key, value in waf[index].items():
            if value:
                if "TX" not in key:
                    waf_key = key
                    waf_value = value
                    break
        for key, value in guideline[i].items():
            if value:
                if "TX" not in key:
                    guideline_key = key
                    guideline_value = value
                    break
        if guideline_key != waf_key or guideline_value != waf_value:
            is_request_header_same = False
            header = guideline_key + guideline_value
            header1 = waf_key + waf_value
            request_header = create_arrray(guideline[i].get("id"), header, header1, guideline[i].get("msg"))
            request_headers.append(request_header)

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

pdf = FPDF()
#By default, there is no page. Add page using add_page
pdf.add_page()
#Before printing text, it is mandatory to select font using set_font
pdf.set_font('Arial', 'B', 30)
#Height, Width, Description,
pdf.cell(0, 20, 'Gods Web', 0, 1, 'C')

pdf.set_font('Arial', '', 10)
description = 'Generated on: ' + str(datetime.now())
pdf.multi_cell(0, 7, description, 0, 1, '')
section_text("This report presents the results of God's Web, which is designed to evaluate the configuration of an OWASP Web Application Firewall (WAF) against the OWASP Core Rule Set (CRS) best practices. The tool assesses whether each CRS rule is present in the WAF configuration and ensures that the security levels of each rule cannot be lower than the CRS guidelines. The results of the audit tool are presented in the following sections, providing key findings and recommendations for improving the WAF configuration to align with CRS best practices.")

section_header("Overview")
section_text("The security level score of the current WAF rules are compared to CRS guideline, the closer the score is to the guideline, the more closely the security level aligns with best practices.")
section_text('Obtained Score: ' + str(waf_score) + ' / ' + str(total_score))
pdf.ln()

section_header("Compliance")
section_text("The following pie chart shows the distribution of WAF rules that are included in the guideline but are not present in the WAF, expressed as a percentage of the total number of WAF rules.")
pdf.image('pie_chart.png', 30, 165, w = 140, h = 120, type = '', link = '')
#pdf.set_y(260) # move cursor position to below the image

pdf.add_page()
section_header("WAF Breakdown")
section_text("The following pie chart shows the distribution of WAF rules that are included in the ModSecurity Core Rule Set (CRS) and custom rules, expressed as a percentage of the total number of WAF rules.")
pdf.image('pie_chart_1.png', 30, 50, w = 140, h = 120, type = '', link = '')
pdf.set_y(160) # move cursor position to below the image
section_text("The following bar graph shows the distribution of WAF rules enabled on the WAF for the most common types of web attacks, as reported by TrustNet")
pdf.image('Bargraph1.png', 30, 175, w = 140, h = 120, type = '', link = '')

pdf.add_page()

section_header("Rule Header")
if is_request_header_same is False:
    section_text("The following rules have different request_header")
    pdf.ln()
    pdf.set_font('Arial', 'B', 12)
    col_width = pdf.w / 1.1
    row_height = pdf.font_size * 2
    for i in range(len(request_headers)):
        message = "Rule ID:" + str(request_headers[i][0])
        pdf.cell(col_width, row_height, message, border=1, align='C')
        pdf.ln()
        pdf.cell(col_width, row_height, 'Description', border=1, align='')
        pdf.ln()
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(col_width, row_height, str(request_headers[i][3]), border=1, align='')
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(col_width, row_height, 'Configured Header', border=1, align='')
        pdf.ln()
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(col_width, row_height, str(request_headers[i][1]), border=1, align='')
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(col_width, row_height, 'Recommended Header', border=1, align='')
        pdf.ln()
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(col_width, row_height, str(request_headers[i][2]), border=1, align='')
        pdf.ln()
        pdf.set_font('Arial', 'B', 12)
else:
    section_text('All rules have the same header')

section_header("Version")
if is_latest_version is False:
    section_text('As of ' + str(datetime.now()) + ', the latest version of ModSecurity Core Rule Set (CRS) is: ' + version + '. The following rules are not using the latest version. Please check the latest version from https://github.com/coreruleset/coreruleset')
    pdf.ln()
    table_3_by_3("Rule ID", "Current Version", "Latest Version", rules1)
else:
    section_text('As of ' + str(datetime.now()) + ', the latest version of ModSecurity Core Rule Set (CRS) is: ' + version + '. All rules are currently using the latest version.')
    
section_header("Severity")
pdf.set_font('Arial', '', 12)
if is_severity_same is False:
    section_text("The severity level of a rule in ModSecurity CRS affects the score that is assigned to a particular event or anomaly detected by that rule. Each severity level has a different weight or impact on the overall score that is calculated for a particular request. \nThe severity levels are as follows: \nCRITICAL (level 5): Indicates that the anomaly detected by the rule is very severe and requires immediate attention. A request that triggers such a rule would be assigned a high score, which would indicate that it is likely an attack. \nERROR (level 4): Indicates that the anomaly is serious and could result in a security breach if not addressed. A request that triggers such a rule would be assigned a high score, which would indicate that it is potentially malicious. \nWARNING (level 3): Indicates that the anomaly is of moderate severity and could potentially lead to a security issue. A request that triggers such a rule would be assigned a lower score than a critical or error-level rule. \nNOTICE (level 2): Indicates that the anomaly is of low severity and may not necessarily indicate an attack or security issue. A request that triggers such a rule would be assigned a low score. \nIt is important to configure the WAF rules based on the severity of the application's security needs. If the configured WAF rules have a lower severity than the OWASP CRS Guideline rules, it may result in a higher risk of successful attacks. \n\nThe following rules have different severity")
    pdf.ln()
    table_3_by_3("Rule ID", "Configured Severity", "Recommended Severity", severitys)
else:
    section_text('All rules are currently using the latest version')

section_header("Action")
pdf.set_font('Arial', '', 12)
if is_action_same is False:
    section_text('In ModSecurity, "pass", "deny", and "block" are actions that can be taken by a rule when a request or response matches that rule.\n "pass" means that the rule will be skipped and the request/response will be allowed to continue through the WAF without being blocked or flagged as an anomaly.\n"deny" means that the request will be blocked, and the client will receive a response indicating that their request was denied.\n"block" is similar to "deny" in that it also blocks the request, but it also generates an event that can be logged and alerts the WAF administrator to the attempted attack.\n\nThese actions are usually associated with the severity level of a rule, with higher severity rules being more likely to "deny" or "block" a request. The specific actions taken by a rule depend on the configuration of the WAF, including the desired level of protection, the sensitivity of the protected application, and the likelihood of false positives.\nHaving current configured rules to have lower restrictive actions such as "pass" when it should be a higher restrictive action such as "deny" can leave the system vulnerable to attacks.\nThe following rules have different actions:')
    pdf.ln()
    table_3_by_3("Rule ID", "Configured Action", "Recommended Action", actions)
else:
    section_text('All rules are currently using the latest version')

pdf.output('test.pdf', 'F')