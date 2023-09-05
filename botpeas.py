from datetime import datetime
from typing import Any

import requests
import datetime
import pathlib
import json
import os
import yaml
import vulners

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
        DESCRIPTION_KEYWORDS_I = keywords_config["DESCRIPTION_KEYWORDS_I"]
        DESCRIPTION_KEYWORDS = keywords_config["DESCRIPTION_KEYWORDS"]
        PRODUCT_KEYWORDS_I = keywords_config["PRODUCT_KEYWORDS_I"]
        PRODUCT_KEYWORDS = keywords_config["PRODUCT_KEYWORDS"]


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
    print(cves)
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
        if cve_time < last_time: #cves TODO change condition
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


def search_exploits(cve: str) -> list:
    ''' Given a CVE it will search for public exploits to abuse it '''

    return []
    # TODO: Find a better way to discover exploits

    vulners_api_key = os.getenv('VULNERS_API_KEY')

    if vulners_api_key:
        vulners_api = vulners.Vulners(api_key=vulners_api_key)
        cve_data = vulners_api.searchExploit(cve)
        return [v['vhref'] for v in cve_data]

    else:
        print("VULNERS_API_KEY wasn't configured in the secrets!")

    return []


#################### GENERATE MESSAGES #########################

def generate_new_cve_message(cve_data: dict) -> str:
    ''' Generate new CVE message for sending to slack '''

    message = f"🚨  *{cve_data['id']}*  🚨\n"
    message += f"🔮  *CVSS*: {cve_data['cvss']}\n"
    message += f"📅  *Published*: {cve_data['Published']}\n"
    message += "📓  *Summary*: "
    message += cve_data["summary"] if len(cve_data["summary"]) < 500 else cve_data["summary"][:500] + "..."

    if cve_data["vulnerable_configuration"]:
        message += f"\n🔓  *Vulnerable* (_limit to 10_): " + ", ".join(cve_data["vulnerable_configuration"][:10])

    message += "\n\n🟢 ℹ️  *More information* (_limit to 5_)\n" + "\n".join(cve_data["references"][:5])

    message += "\n"

    # message += "\n\n(Check the bots description for more information about the bot)\n"

    return message


def generate_modified_cve_message(cve_data: dict) -> str:
    ''' Generate modified CVE message for sending to slack '''

    message = f"📣 *{cve_data['id']}*(_{cve_data['cvss']}_) was modified the {cve_data['last-modified'].split('T')[0]} (_originally published the {cve_data['Published'].split('T')[0]}_)\n"
    return message


def generate_public_expls_message(public_expls: list) -> str:
    ''' Given the list of public exploits, generate the message '''

    message = ""

    if public_expls:
        message = "😈  *Public Exploits* (_limit 20_)  😈\n" + "\n".join(public_expls[:20])

    return message


#################### SEND MESSAGES #########################

def send_teams_mesage(cve_data: dict):
    """ Send a message to the teams channel """

    teams_url = "https://senthorussa.webhook.office.com/webhookb2/b33deea3-b61b-4a12-8d59-1fcee59e1b50@24673957-1a8b-41a5-be4c-dd7214932784/IncomingWebhook/7db687461d6c4aa3a4dab3d5d3cc790f/4519b03f-1baf-446d-94fc-587e8d095985"  # os.getenv('TEAMS_WEBHOOK')

    if not teams_url:
        print("SLACK_WEBHOOK wasn't configured in the secrets!")
        return

    json_params = {
        "@type": "MessageCard",
        "summary": "CVEs report from BotPEASS",
        "sections": [{
            "activityTitle": "CVEs report from BotPEASS",
            "facts": [{
                "name": "Modified",
                "value": cve_data['last-modified'].split('T')[0]
            }, {
                "name": "Published",
                "value": cve_data['Published'].split('T')[0]
            }, {
                "name": "access",
                "value": " "
            }, {
                "name": "assigner",
                "value": ""
            }, {
                "name": "cvss",
                "value": cve_data["cvss"]
            }, {
                "name": "cwe",
                "value": cve_data["cwe"]
            }, {
                "name": "id",
                "value": cve_data["id"]
            }, {
                "name": "impact",
                "value": ""
            }, {
                "name": "last-modified",
                "value": ""
            }, {
                "name": "references",
                "value": ""
            }, {
                "name": "summary",
                "value": ""
            }

            ],
            "markdown": True
        }]
    }

    requests.post(teams_url, json=json_params)



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

    for new_cve in new_cves:
        send_teams_mesage(new_cve)
        #public_exploits = search_exploits(new_cve['id'])
        cve_message = generate_new_cve_message(new_cve)
        #public_expls_msg = generate_public_expls_message(public_exploits)
        break


    # Find and publish modified CVEs
    modified_cves = get_modified_cves()

    modified_cves = [mcve for mcve in modified_cves if not mcve['id'] in new_cves_ids]
    modified_cves_ids = [mcve['id'] for mcve in modified_cves]
    print(f"Modified CVEs discovered: {modified_cves_ids}")

    for modified_cve in modified_cves:
        #public_exploits = search_exploits(modified_cve['id'])
        cve_message = generate_modified_cve_message(modified_cve)
        #public_expls_msg = generate_public_expls_message(public_exploits)

    update_lasttimes()


if __name__ == "__main__":
    main()
