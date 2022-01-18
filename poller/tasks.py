import importlib
import requests
import os
import glob
import json
import timeout_decorator

@timeout_decorator.timeout(10)
def execute_rule(rule,event):
    uuid = os.path.splitext(os.path.basename(rule))[0]
    module_name = "{}.{}".format("rules",uuid)
    module = importlib.import_module(module_name)
    return getattr(module,"uuid_{}".format(uuid))(event)

#@timeout_decorator.timeout(BLOCK_TIMEOUT)
def execute_event_against_rules(event,logging,**kwargs):
    hits = []
    for rule in glob.glob("rules/*.py"):
        try:
            result = execute_rule(rule,event)
            if result["hit"]:
                hits.append(result)
        except Exception as e:
            logging.warning("Exception:{} while executing rule:{} for event:{}".format(str(e),rule,event["uid"]))
    return hits

def clean_rules_directory():
    for rule in glob.glob("rules/*.py"):
       os.remove(rule)
    return True

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
    clean_rules_directory()
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
    for event in events.json():
#haaaaaaa
        logging.debug("Running event:{} against rules".format(event["uid"]))
        # execute all rules against the event
        hits = execute_event_against_rules(event,logging)
        if hits:
            logging.debug("Event:{} has {} hits".format(event["uid"],len(hits)))
            data.append({"uid":event["uid"],"hits":hits})
    """
    # post results
    logging.debug("Posting results to {}".format(results_url))
    results = requests.post(url=results_url,verify=verify)
    if not results.ok:
        logging.warning("Unable to POST results to {}. Status code: {}. Warning:{}".format(results_url,
            results.status_code,results.text))
        return False
    """
