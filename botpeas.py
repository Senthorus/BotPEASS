from datetime import datetime
from typing import Any

import time
import requests
import datetime
import pathlib
import json
import os
import yaml

from os.path import join
from enum import Enum

CIRCL_LU_URL = "https://cve.circl.lu/api/query"
CVES_JSON_PATH = join(pathlib.Path(__file__).parent.absolute(), "output/botpeas.json")
LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

KEYWORDS_CONFIG_PATH = join(pathlib.Path(__file__).parent.absolute(), "config/botpeas.yaml")
ALL_VALID = False
DESCRIPTION_KEYWORDS_I = []
DESCRIPTION_KEYWORDS = []
PRODUCT_KEYWORDS_I = []
PRODUCT_KEYWORDS = []


class Time_Type(Enum):
    PUBLISHED = "Published"
    LAST_MODIFIED = "last-modified"


################## LOAD CONFIGURATIONS ####################

def load_keywords():
    """ Load keywords from config file """

    global ALL_VALID
    global DESCRIPTION_KEYWORDS_I, DESCRIPTION_KEYWORDS
    global PRODUCT_KEYWORDS_I, PRODUCT_KEYWORDS

    with open(KEYWORDS_CONFIG_PATH, 'r') as yaml_file:
        keywords_config = yaml.safe_load(yaml_file)
        print(f"Loaded keywords: {keywords_config}")
        ALL_VALID = keywords_config["ALL_VALID"]
        DESCRIPTION_KEYWORDS_I = [] if keywords_config["DESCRIPTION_KEYWORDS_I"] is None else keywords_config["DESCRIPTION_KEYWORDS_I"]
        DESCRIPTION_KEYWORDS = [] if keywords_config["DESCRIPTION_KEYWORDS"] is None else keywords_config["DESCRIPTION_KEYWORDS"]
        PRODUCT_KEYWORDS_I = [] if keywords_config["PRODUCT_KEYWORDS_I"] is None else keywords_config["PRODUCT_KEYWORDS_I"]
        PRODUCT_KEYWORDS = [] if keywords_config["PRODUCT_KEYWORDS"] is None else keywords_config["PRODUCT_KEYWORDS"]


def load_lasttimes():
    """ Load lasttimes from json file """

    global LAST_NEW_CVE, LAST_MODIFIED_CVE

    try:
        with open(CVES_JSON_PATH, 'r') as json_file:
            cves_time = json.load(json_file)
            LAST_NEW_CVE = datetime.datetime.strptime(cves_time["LAST_NEW_CVE"], TIME_FORMAT)
            LAST_MODIFIED_CVE = datetime.datetime.strptime(cves_time["LAST_MODIFIED_CVE"], TIME_FORMAT)

    except Exception as e:  # If error, just keep the fault date (today - 1 day)
        print(f"ERROR, using default last times.\n{e}")
        pass

    print(f"Last new cve: {LAST_NEW_CVE}")
    print(f"Last modified cve: {LAST_MODIFIED_CVE}")


def update_lasttimes():
    """ Save lasttimes in json file """

    with open(CVES_JSON_PATH, 'w') as json_file:
        json.dump({
            "LAST_NEW_CVE": LAST_NEW_CVE.strftime(TIME_FORMAT),
            "LAST_MODIFIED_CVE": LAST_MODIFIED_CVE.strftime(TIME_FORMAT),
        }, json_file)


################## SEARCH CVES ####################

def get_cves(tt_filter: Time_Type) -> dict:
    """ Given the headers for the API retrieve CVEs from cve.circl.lu """
    now = datetime.datetime.now() - datetime.timedelta(days=7)
    now_str = now.strftime("%d-%m-%Y")

    headers = {
        "time_modifier": "from",
        "time_start": now_str,
        "time_type": tt_filter.value,
        "limit": "100",
    }
    r = requests.get(CIRCL_LU_URL, headers=headers)

    return r.json()


def get_new_cves() -> list:
    """ Get CVEs that are new """

    global LAST_NEW_CVE

    cves = get_cves(Time_Type.PUBLISHED)
    filtered_cves, new_last_time = filter_cves(
        cves["results"],
        LAST_NEW_CVE,
        Time_Type.PUBLISHED
    )
    LAST_NEW_CVE = new_last_time

    return filtered_cves


def get_modified_cves() -> list:
    """ Get CVEs that has been modified """

    global LAST_MODIFIED_CVE

    cves = get_cves(Time_Type.LAST_MODIFIED)
    filtered_cves, new_last_time = filter_cves(
        cves["results"],
        LAST_MODIFIED_CVE,
        Time_Type.PUBLISHED
    )
    LAST_MODIFIED_CVE = new_last_time

    return filtered_cves


def filter_cves(cves: list, last_time: datetime.datetime, tt_filter: Time_Type) -> tuple[list[Any], datetime]:
    """ Filter by time the given list of CVEs """

    filtered_cves = []
    new_last_time = last_time

    for cve in cves:
        cve_time = datetime.datetime.strptime(cve[tt_filter.value], TIME_FORMAT)
        if cve_time > last_time:
            if ALL_VALID or is_summ_keyword_present(cve["summary"]) or \
                    is_prod_keyword_present(str(cve["vulnerable_configuration"])):
                filtered_cves.append(cve)

        if cve_time > new_last_time:
            new_last_time = cve_time

    return filtered_cves, new_last_time


def is_summ_keyword_present(summary: str):
    """ Given the summary check if any keyword is present """

    return any(w in summary for w in DESCRIPTION_KEYWORDS) or \
        any(w.lower() in summary.lower() for w in DESCRIPTION_KEYWORDS_I)


def is_prod_keyword_present(products: str):
    """ Given the summary check if any keyword is present """

    return any(w in products for w in PRODUCT_KEYWORDS) or \
        any(w.lower() in products.lower() for w in PRODUCT_KEYWORDS_I)


#################### SEND MESSAGES #########################

def send_teams_mesage(cve_data: dict):
    """ Send a message to the teams channel """

    teams_url = os.getenv('TEAMS_WEBHOOK_DEV')

    if not teams_url:
        print("TEAMS_WEBHOOK wasn't configured in the secrets!")
        return

    references = ""
    for link in cve_data['references']:
        if references != "":
            references += "\r"
        references += " - [" + link + "](" + link + ")"

    json_params = {
        "@type": "MessageCard",
        "summary": "CVEs report from BotPEASS",
        "sections": [{
            "activityTitle": "CVEs report from BotPEASS",
            "facts": [{
                "name": "Modified",
                "value": str(cve_data['Modified'])
            }, {
                "name": "Published",
                "value": str(cve_data['Published'])
            }, {
                "name": "cvss",
                "value": str(cve_data["cvss"])
            }, {
                "name": "cwe",
                "value": cve_data["cwe"]
            }, {
                "name": "id",
                "value": cve_data["id"]
            }, {
                "name": "last-modified",
                "value": cve_data['last-modified']
            }, {
                "name": "references",
                "value": references
            }, {
                "name": "summary",
                "value": cve_data['summary']
            }
            ],
            "markdown": True
        }]
    }

    response = requests.post(teams_url, json=json_params)
    if response.status_code != 200:
        print("ERROR: message for CVE ", cve_data['id'], " was not sent" )


def send_teams_mesage_empty():
    """ Send a message to the teams
    channel """

    teams_url = os.getenv('TEAMS_WEBHOOK_DEV')

    if not teams_url:
        print("TEAMS_WEBHOOK_DEV wasn't configured in the secrets!")
        return

    keywords = ""
    for key in DESCRIPTION_KEYWORDS_I:
        if keywords != "":
            keywords += "\r"
        keywords += " - " + key

    json_params = {
        "@type": "MessageCard",
        "summary": "CVEs report from BotPEASS",
        "sections": [{
            "activityTitle": "CVEs report was empty",
            "facts": [{
                "name": "Keywords list",
                "value": keywords
            }
            ],
            "markdown": True
        }]
    }

    response = requests.post(teams_url, json=json_params)
    if response.status_code != 200:
        print("ERROR: message for CVE ")

#################### MAIN #########################

def main():
    # Load configured keywords
    load_keywords()

    # Start loading time of last checked ones
    load_lasttimes()

    # Find a publish new CVEs
    new_cves = get_new_cves()

    new_cves_ids = [ncve['id'] for ncve in new_cves]
    print(f"New CVEs discovered: {new_cves_ids}")
    if new_cves == []:
        send_teams_mesage_empty()
    for new_cve in new_cves:
        send_teams_mesage(new_cve)
        time.sleep(0.2)

    # Find and publish modified CVEs
    modified_cves = get_modified_cves()

    modified_cves = [mcve for mcve in modified_cves if not mcve['id'] in new_cves_ids]
    modified_cves_ids = [mcve['id'] for mcve in modified_cves]
    print(f"Modified CVEs discovered: {modified_cves_ids}")

    update_lasttimes()


if __name__ == "__main__":
    main()
