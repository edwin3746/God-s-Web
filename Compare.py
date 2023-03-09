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
    print("Number of rules:", len(guideline))
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

    # Calculate average weighted score per rule
    #print("Total weighted score:", round(total_weighted_score, 2))

    #return guideline
    return round(total_weighted_score, 2)

#Extract Violation and count from modsec_audit.log
def parse_rule_violations(log_file):
    rule_violations = {}
    current_violation = None
    
    with open(log_file, "r") as file:
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
            print("hehe no call needed")
            return explanation

    #Else make call
    url = 'https://api.regexplain.ai/api/v1/explain'
    data = {'regex': regex}
    headers = {'Content-Type':'application/json'}
    response = requests.post(url,json=data,headers=headers)
    explanation = response.text
    explanation_trim = explanation.index("This") + len("This")
    explanation_trim1 = explanation.index('"}', explanation_trim)
    trimmed_sentece = explanation[explanation_trim: explanation_trim1].strip()
    trimmed_sentece = "This " + trimmed_sentece
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
waf = open_json("waf.json")
#waf = open_json("Guideline.json")

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
print(version)
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
#Count the number of rules related to Top 5 web attacks
#attacks = {"XSS": 0, "SQL": 0, "Path Traversal": 0, "File Inclusion": 0, "DDoS": 0, "Others": 0}
#for rules in waf:
#    if "xss" in str(rules.values()).lower():
#        attacks["XSS"] += 1
#    elif "sql" in str(rules.values()).lower():
#        attacks["SQL"] += 1
#    elif "path traversal" in str(rules.values()).lower():
#        attacks["Path Traversal"] += 1
#    elif "file inclusion" in str(rules.values()).lower():
#        attacks["File Inclusion"] += 1
#    elif "dos" in str(rules.values()).lower():
#        attacks["DDoS"] += 1
#    else:
#        attacks["Others"] += 1

#plt.clf()
#proportions = np.array(list(attacks.values()))
#labels = np.array(list(attacks.keys()))
#colors = ['red','orange','yellow','green','blue','violet']
#3plt.bar(labels, proportions, color=colors)
# Set the tick positions and labels
#plt.xticks(np.arange(len(labels)), labels)
# Adjust the spacing of the labels
#plt.gcf().autofmt_xdate(rotation=45)
#plt.savefig("Bargraph1.png")
#total_score = calculate_score(guideline)af_score = calculate_score(waf)
#
total_score = calculate_weighted_scores("Guideline.json")
waf_score = calculate_weighted_scores("waf.json")
#print(total_score)
#print(waf_score)
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
            if is_request_header_same == None:
                explanation = explain_regex(header, guideline[i].get("id"), "guideline")
                explanation1 = explain_regex(header, waf[index].get("id"), "waf")
            is_request_header_same = False
            request_header = create_arrray(guideline[i].get("id"), header, header1, guideline[i].get("msg"))
            request_header.append(explanation)
            request_header.append(explanation1)
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
pdf.image('pie_chart_1.png', 30, 50, w = 140, h = 120, type = '', link = '')
pdf.set_y(160)


pdf.add_page()
section_header("Rule Variables")
if is_request_header_same is False:
    section_text("Variables in ModSecurity rule are used to define conditions that trigger specific actions, such as blocking or logging a request")
    pdf.ln()
    section_text("If ModSecurity variables are set incorrectly, it can lead to unexpected behavior or errors in the rules processing. This can result in the rules not functioning as intended, or potentially blocking legitimate traffic.\n\nThe following rules have different variables configured: ")
    col_width = pdf.w / 1.1
    row_height = pdf.font_size * 2
    for i in range(len(request_headers)):
        pdf.set_font('Arial', 'B', 12)
        message = "Rule ID:" + str(request_headers[i][0])
        pdf.cell(col_width, row_height, message, border=1, align='C')
        pdf.ln()
        table_variable("Description", str(request_headers[i][3]))
        text_latin1 = unicodedata.normalize('NFKD', str(request_headers[i][1])).encode('latin-1', 'ignore').decode('latin-1')
        table_variable("Configured Variable", text_latin1)
        table_variable("Configured Regex Explanation", str(request_headers[i][5]))
        text_latin2 = unicodedata.normalize('NFKD', str(request_headers[i][2])).encode('latin-1', 'ignore').decode('latin-1')
        table_variable("Recommended Variable", text_latin2)
        table_variable("Recommended Regex Explanation", str(request_headers[i][4]))
        pdf.ln()
else:
    section_text('All rules have the same header')

section_header("Version")
if is_latest_version is False:
    section_text('As of ' + str(datetime.now()) + ', the latest version of ModSecurity Core Rule Set (CRS) is: ' + version + '. The following rules are not using the latest version. Please check the latest version from https://github.com/coreruleset/coreruleset')
    pdf.ln()
    table_3_by_3("Rule ID", "Current Version", "Latest Version", rules1)
else:
    section_text('As of ' + str(datetime.now()) + ', the latest version of ModSecurity Core Rule Set (CRS) is: ' + version + '. All rules are currently using the latest version.')
    
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

pdf.add_page()
section_header("Scoring")
section_text('The OWASP CRS anomaly scoring system is derived by combining two factors: severity and paranoia level, with severity carrying a higher weight than paranoia level.\n\n')
action1 = [['Severity', 'Is determined by the type of attack and the potential impact it could have on the system.'], ['Paranoia', 'Reflects the likelihood that the rule could generate false positives or block legitimate traffic.']]
table_2_by_2(action1)
pdf.ln()
section_text("The aim should be to achieve a score as close as possible to the score of the OWASP CRS Guideline. This indicates that the WAF configuration is aligned with the best practices outlined in the guideline.\nHowever, having a higher severity or paranoia level does not necessarily mean a rule is more secure. It means that the rule is more likely to detect and potentially block an attack that matches the rule's criteria. A rule with a high anomaly score is more likely to detect more sophisticated attacks, but it also increases the risk of false positives.\nIt is important to note that the anomaly scoring is just one aspect of WAF configuration management. Other factors such as the accuracy of the rules, false positives, and false negatives should also be considered in determining the effectiveness of the WAF. Please consider these factors with your organization's security objectives")
pdf.ln()
section_text('Obtained Score: ' + str(waf_score) + ' / ' + str(total_score))
if waf_score > total_score:
    section_text("Your average weighted score exceeds the guideline by a significant amount. This suggests that your WAF may be too aggressive in blocking traffic. You may experience higher detection of false positives, where legitimate traffic is blocked or denied. You can adjust the WAF configuration to lower the overall weighted score and bring it closer to the guideline. This can be done by tuning the paranoia level and severity of the rules in the WAF configuration. You can also review the rules in the WAF that are not in the guideline and disable them if they are not needed.")
elif waf_score >= total_score * 0.95 and waf_score <= total_score * 1.05:
    section_text("Your average weighted score is near or equals to the guideline. Please continue to perform regular audits to maintain the best practices as per the guideline.")
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
pdf.output(str(datetime.now()) + '.pdf', 'F')
