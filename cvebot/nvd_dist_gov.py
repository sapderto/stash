import requests
import os
import os.path
import json
import datetime
from bs4 import BeautifulSoup

initial_state = False
initial_state_filename = "nvd_dist_gov_init.json"


def request():
    returnable = list()
    request_data = requests.get(
        f"https://nvd.nist.gov/vuln/full-listing/{datetime.datetime.now().year}/{datetime.datetime.now().month}").text
    soup = BeautifulSoup(request_data, features="html.parser")
    cves = soup.find_all("span", attrs={"class": "col-md-2"})
    for c in cves:
        cve = c.findChildren("a", recursive=False)[0]
        returnable.append(cve.text)
    return returnable


def get_new():
    global initial_state
    if not initial_state:
        if os.path.exists(initial_state_filename):
            with open(initial_state_filename, "r") as fi:
                initial_state = json.load(fi)
        else:
            initial_state = request()
            with open(initial_state_filename, "w") as fi:
                json.dump(initial_state, fi)
    current_state = request()
    if current_state == initial_state:
        print("No new data")
        return False
    else:
        difference = [str("https://nvd.nist.gov/vuln/detail/" + x) for x in current_state if x not in initial_state]
        print(difference)
        return difference
