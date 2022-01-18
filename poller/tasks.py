import requests
import os
import json
from utils import helpers

def get_rules(app, logging):
    if not app.UI_HOST:
        logging.error("UI_HOST env variable is not set")
        return False
    verify = True
    if app.DISABLE_TLS_VALIDATION == "1":
        verify = False
    rules_url = "{}{}".format(app.UI_HOST,app.RULES_ENDPOINT)
    logging.debug("Querying {} for rules".format(rules_url))
    rules = requests.get(url=rules_url,verify=verify)
    if not rules.ok:
        logging.warning("Unable to gather rules from {}. Status code: {}. Warning:{}".format(rules_url,
            rules.status_code,rules.text))
        return False
    logging.debug("Gathered {} rules from {}".format(len(rules.json()),app.UI_HOST))
    helpers.clean_rules_directory()
    for rule in rules.json():
        if rule["enabled"]:
            with open("rules/{}.py".format(rule["uuid"]),"w") as f:
                f.write(rule["code"])
    return True

def execute_rules(app, logging):
    data = []
    if not app.UI_HOST:
        logging.error("UI_HOST env variable is not set")
        return False
    verify = True
    if app.DISABLE_TLS_VALIDATION == "1":
        verify = False
    events_url = "{}{}".format(app.UI_HOST,app.EVENTS_ENDPOINT)
    results_url = "{}{}".format(app.UI_HOST,app.RESULTS_ENDPOINT)

    # get events
    logging.debug("Querying {} for events".format(events_url))
    events = requests.get(url=events_url,verify=verify)
    if not events.ok:
        logging.warning("Unable to gather rules from {}. Status code: {}. Warning:{}".format(events_url,
            events.status_code,events.text))
        return False
    logging.debug("Gathered {} events".format(len(events.json())))
    for event in events.json():
        logging.debug("Running event:{} against rules".format(event["uid"]))
        hits = helpers.execute_event_against_rules(event,logging)
        logging.debug("Event:{} has {} hits".format(event["uid"],len(hits)))
        data.append({"id":event["id"],"count":len(hits),"hits":hits})
    if not data:
        return True

    # post results
    logging.debug("Posting results to {}".format(results_url))
    results = requests.post(url=results_url,json=data,verify=verify)
    if not results.ok:
        logging.warning("Unable to POST results to {}. Status code: {}. Warning:{}".format(results_url,
            results.status_code,results.text))
        return False
    logging.debug("Response from results endpoint:{}".format(str(results.json())))
    return True
