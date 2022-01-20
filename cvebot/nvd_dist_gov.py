import time

import requests
import os
import os.path
import json
import re
import datetime
import googletrans
import logging
import sqlite3
#import eventlet
from bs4 import BeautifulSoup

initial_state = False
initial_state_filename = "nvd_dist_gov.db"


#import signal

#class TimeoutExceptionPr(Exception):
#    pass

#def timeout_handler(signum, frame):
#    raise TimeoutExceptionPr

#signal.signal(signal.SIGALRM, timeout_handler)

def add_testing(cve_dict):
    connection = sqlite3.connect(initial_state_filename)
    cursor = connection.cursor()
    needable = ['affected', 'description', 'description_ru', 'solution', 'link', 'metrics',
                'appear_time', 'update_time']
    for n in needable:
        if n not in cve_dict:
            cve_dict[n] = ''
    cursor.execute(
        """INSERT INTO testing(id, affected, description, description_ru, solution, link, metrics, appear_time,
        update_time) VALUES(:id, :affected, :description,:description_ru,:solution,:link,:metrics,:appear_time,
        :update_time)""", cve_dict)
    connection.commit()


#def try_to_get_affected(cve):
#    original_sigalrm_handler = signal.getsignal(signal.SIGALRM)
#    signal.signal(signal.SIGALRM, timeout_handler) 
#    logging.info(f"Starting to get affected {cve['id'] if 'id' in cve else ''}")
#    print(f"Starting to get affected {cve['id'] if 'id' in cve else ''}")
#    fixed_pattern = r"(?<=([Ff]ixed))([\w\-\,\ ]+)(([A-Zg][\w\-\.\,]*\ ?)(((((([A-Z]+)|([\d]+))(-[A-Z])?[\w\d\.\(\+]+,?)*)|(to)|(prior)|(plugin)|(before)|(and)|(software)|(versions)|(up)|(\(All)|(<))( )?)+(?=(v?\d(\d*(\.|[rp+])?(\d)*)+(\))?)))"
#    version_pattern = r"(([A-Zg][\w-]*\ ?)(((((([A-Z]+)|([\d]+))(-[A-Z])?[\w\d\.\(\+]+,?)*)|(to)|(prior)|(plugin)|(before)|(and)|(software)|(versions)|(in)|(through)|(up)|(\(All)|(<))( )?)+(?=(v?\d(\d*(\.|[rp+])?(\d)*)+(\))?)))"
#    start_pattern = r"^((([A-Za-z@](\w)+)([\w\+\,\ \-\.]))*)(?=(is ))"
#    # print("predescription")
#    description = cve['description']
#    #eventlet.monkey_patch()
#    fixed_find = []
#    signal.alarm(10)
#    try:
#        fixed_find = re.findall(fixed_pattern, description)
#    except TimeoutExceptionPr:
#        logging.warn("Regex terminated after timeout")
#    # print(fixed_find)
#    # print("fixed_find")
#    # print(fixed_find)
#    if fixed_find:
#        # print("Processing fixed")
#        tmp = ''
#        for f in fixed_find:
#            tmp = max(tmp, f[2] + f[-5])
#        fixed_find = tmp
#        cve['solution'] = "Update to {}".format(fixed_find)
#    else:
#        #print("Skipping fixed")
#        fixed_find = ''
#    #print("prestart label")
#    #print(description)
#    start_find = []
#    signal.alarm(10)
#    try:
#        start_find = re.findall(start_pattern, description)
#    except TimeoutExceptionPr:
#        logging.warn("Regex terminated after timeout")
#        #print(str(e))
#        #start_find = []
#    # print(start_find)
#    #print("start_find")
#    #print(start_find)
#    if start_find:
#        start_find = start_find[0][0]
#    else:
#        start_find = ''
#    #print("preversion label")
#    version_find = []
#    signal.alarm(10)
#    try:
#        version_find = re.findall(version_pattern, description)
#    except TimeoutExceptionPr:
#        logging.warn("Regex terminated after timeout")
#    # print(version_find)
#    #print("version_find")
#    if version_find:
#        tmp = ''
#        for f in version_find:
#            tmp = max(tmp, f[0] + (f[-4] if f[-4] else f[-5]))
#        version_find = tmp
#        if version_find[:2] == "g ":
#            version_find = ''
#    else:
#        version_find = ''
#    if not (start_find.strip() == '' and version_find.strip() == '' and fixed_find.strip() == ''):
#        if max(start_find.strip(), version_find.strip(), fixed_find.strip()) == fixed_find.strip():
#            cve['affected'] = "< {}".format(fixed_find.strip())
#        else:
#            # print("Probably not fixed still, trying use another reg")
#            #print(f"Start find: {start_find}")
#            #print(f"Version_find: {version_find}")
#            #print(f"Fixed_find: {fixed_find}")
#            try:
#                if start_find:
#                    #print("Using start pattern")
#                    cve['affected'] = start_find.strip()
#                else:
#                    #print("Using last able option")
#                    #print(max(start_find.strip(), version_find.strip(), fixed_find.strip()))
#                    cve['affected'] = max(start_find.strip(), version_find.strip(), fixed_find.strip())
#            except BaseException as e:
#                logging.warning(str(e))
#    signal.signal(signal.SIGALRM, original_sigalrm_handler )


def add_processed(cve_dict):
    connection = sqlite3.connect(initial_state_filename)
    cursor = connection.cursor()
    needable = ['affected', 'description', 'description_ru', 'solution', 'link', 'metrics',
                'appear_time', 'update_time']
    for n in needable:
        if n not in cve_dict:
            cve_dict[n] = ''
    cursor.execute(
        """INSERT INTO processed(id, affected, description, description_ru, solution, link, metrics, appear_time,
        update_time) VALUES (:id,:affected,:description,:description_ru,:solution,:link,:metrics,:appear_time,
        :update_time)""", cve_dict)
    connection.commit()


def add_skipping(cve_dict):
    #initial_state = False
    connection = sqlite3.connect(initial_state_filename)
    cursor = connection.cursor()
    needable = ['affected', 'description', 'description_ru', 'solution', 'link', 'metrics',
                'appear_time', 'update_time']
    for n in needable:
        if n not in cve_dict:
            cve_dict[n] = ''
    cursor.execute(
        """INSERT INTO skipping(id, affected, description, description_ru, solution, link, metrics, appear_time,
        update_time) VALUES (:id,:affected,:description,:description_ru,:solution,:link,:metrics,:appear_time,
        :update_time)""", cve_dict)
    connection.commit()


def get_state():
    sqlite_connection = sqlite3.connect(initial_state_filename)
    cursor = sqlite_connection.cursor()
    cursor.execute("SELECT id FROM processed")
    state = cursor.fetchall()
    cursor.execute("SELECT id FROM skipping")
    state.extend(cursor.fetchall())
    cursor.execute("SELECT id FROM testing")
    state.extend(cursor.fetchall())
    return list(set([element for tupl in state for element in tupl]))


def request():
    logging.info("Requesting new data")
    returnable = list()
    while True:
        try:
            request_data = requests.get(
                f"https://nvd.nist.gov/vuln/full-listing/{datetime.datetime.now().year}/{datetime.datetime.now().month}").text
            break
        except requests.exceptions.ConnectionError as e:
            logging.error(str(e))
            time.sleep(5)
            continue

    soup = BeautifulSoup(request_data, features="html.parser")
    cves = soup.find_all("span", attrs={"class": "col-md-2"})
    for c in cves:
        cve = c.findChildren("a", recursive=False)[0]
        returnable.append(cve.text)
    return returnable


def enrich_base(cve_dict):
    logging.info(f"Starting enriching {cve_dict['id']}")
    if 'link' not in cve_dict:
        cve_dict["link"] = str("https://nvd.nist.gov/vuln/detail/" + cve_dict["id"])
    work_link=''
    if "\n" in cve_dict["link"]:
        work_link = cve_dict["link"].split("\n")[0]
    else:
        work_link = cve_dict["link"]
    clear_link = requests.get(cve_dict['link'], timeout=5)
    if clear_link:
        data = BeautifulSoup(clear_link.text, features="html.parser")
    else:
        return False
    status = True#(data.find("span", attrs={"data-testid": "vuln-warning-status-name"}) is None)                                                                    #(data.find("div", attrs={"data-testid": "vuln-warning-alert-container"}) is None) 
 #(data.find("span", attrs={"data-testid": "vuln-warning-status-name"}) is None)
    search_descr = data.find("p", attrs={"data-testid": "vuln-description"})
    cve_dict['appear_time'] = datetime.datetime.now().strftime("%d:%m:%YT%H:%M:%S")
    if search_descr:
        cve_dict["description"] = search_descr.text
        if "** REJECT **" not in cve_dict["description"]:
            try:
                logging.debug(f"Translating text: {search_descr.text}")
                cve_dict["description_ru"] = str(
                    googletrans.Translator().translate(search_descr.text, dest='ru').text).strip()
            except Exception as e:
                logging.warning(str(e))
        #try_to_get_affected(cve_dict)
        logging.info("Affected search finished, searching metrics")
    metrics = ''
    cvss3_text = data.find("strong", text="CVSS 3.x Severity and Metrics:")
    if cvss3_text:
        for x in cvss3_text.parent.findChildren("div", attrs={'class': "row no-gutters"}):
            tmp_cvss_score = x.findChild("span", attrs={'class': 'severityDetail'}).text.strip()
            tmp_cvss_vector = x.findChild("strong", text="Vector:")
            if tmp_cvss_vector:
                tmp_cvss_vector = tmp_cvss_vector.find_next("span").text
            metrics += f"({tmp_cvss_score}) {tmp_cvss_vector}\n"
            # print(x.findChild("span", attr={"class":"severityDetail"}).text)
    logging.info("CVSS3 metrics processing finished")
    cvss2_text = data.find("strong", text="CVSS 2.0 Severity and Metrics:")
    if cvss2_text:
        for x in cvss2_text.parent.findChildren("div", attrs={'class': "row no-gutters"}):
            tmp_cvss_score = x.findChild("span", attrs={'class': 'severityDetail'}).text.strip()
            tmp_cvss_vector = x.findChild("strong", text="Vector:")
            if tmp_cvss_vector:
                tmp_cvss_vector = tmp_cvss_vector.find_next("span").text
            metrics += f"({tmp_cvss_score}) {tmp_cvss_vector}\n"
            # print(x.findChild("span", attr={"class":"severityDetail"}).text)
    logging.info("CVSS2 metrics processing finished")
    if metrics:
        cve_dict['metrics'] = metrics.strip()
    links_iter = 0
    links_summary = ''
    tag_of_link_in_table = data.find("td", attrs={'data-testid': f"vuln-hyperlinks-link-{links_iter}"})
    while tag_of_link_in_table:
        if tag_of_link_in_table.findChild("a"):
            links_summary += str(tag_of_link_in_table.findChild("a").text + "\n")
            links_iter += 1
            tag_of_link_in_table = data.find("td", attrs={'data-testid': f"vuln-hyperlinks-link-{links_iter}"})
        else:
            break
    cwe_iter = 0
    tag_of_cwe_in_table = data.find_all("td", attrs={'data-testid': f"vuln-CWEs-link-{cwe_iter}"})
    while tag_of_cwe_in_table:
        if len(tag_of_cwe_in_table) == 2:
            cwe_id = tag_of_cwe_in_table[0].findChild("a")
            cwe_description = tag_of_cwe_in_table[1]
            if cwe_id and cwe_description:
                links_summary += f"({cwe_id.text} {cwe_description.text}) {cwe_id['href']}\n"
        cwe_iter += 1
        tag_of_cwe_in_table = data.find_all("td", attrs={'data-testid': f"vuln-CWEs-link-{cwe_iter}"})
    if links_summary:
        cve_dict['link'] += str("\n"+links_summary)
    logging.info("Links processing is finished")
    appear_time = data.find("span", attrs={"data-testid":"vuln-published-on"})
    if appear_time:
        cve_dict['appear_time'] = appear_time.text.strip()
    update_time = data.find("span", attrs={"data-testid":"vuln-last-modified-on"})
    if update_time:
        cve_dict['update_time'] = update_time.text.strip()
    if "description" not in cve_dict:
        logging.warning(f"Skipping {cve_dict['id']} in cause of missing description")
        return False
    if "** REJECT **" in cve_dict["description"]:
        add_skipping(cve_dict)
        logging.info(f"Skipping {cve_dict['id']} in cause of reject")
        #del cve_dict
        initial_state.append(cve_dict['id'])
        del cve_dict
        return False
    if not status:
        add_testing(cve_dict)
        logging.info(f"Testing {cve_dict['id']} in cause of warning")
        return False
    return True


def commit_state(state):
    logging.info(f"Commiting state for {state['id']}")
    global initial_state
    initial_state.append(state['id'])
    add_processed(state)


def get_new():
    global initial_state
    if not initial_state:
        initial_state = get_state()
    current_state = request()
    if current_state == initial_state:
        logging.info("difference was not found")
        return False
    else:
        difference = [{"id": x} for x in current_state if x not in initial_state]
        if len(difference)>30:
            difference = difference[:30]
        logging.info(f"Processing difference {[x['id'] for x in difference]}")
        #initial_state = current_state
        initial_state.extend(difference)
        returnable = []
        for e in difference:
            e["link"] = str("https://nvd.nist.gov/vuln/detail/" + e["id"])
            if not enrich_base(e):
                print(f"Searching {e} in {difference} is {e in difference}")
            else:
                returnable.append(e)
        logging.info(f"Returning difference {returnable}")
        return returnable


if __name__ == "__main__":
    print(get_state())
