import importlib
import arrow
import requests
import os
import glob
import json

def clean_rules_directory():
    for rule in glob.glob("rules/*.py"):
       os.remove(rule)
    return True

#@timeout_decorator.timeout(BLOCK_TIMEOUT)
def execute_event_against_rules(event,logging,**kwargs):
    hits = []
    for rule in glob.glob("rules/*.py"):
        try:
            uuid = os.path.splitext(os.path.basename(rule))[0]
            module_name = "{}.{}".format("rules",uuid)
            module = importlib.import_module(module_name)
            result = getattr(module,"uuid_{}".format(uuid))(event)
            if result["hit"]:
                hits.append(result)
        except Exception as e:
            logging.warning("Exception:{} while executing rule:{} for event:{}".format(str(e),rule,event["uid"]))
    logging.debug("Successfully execution event:{} against all rules".format(event["uid"]))
    return hits

def get_rules(app, logging):
    if not app.UI_HOST:
        logging.error("UI_HOST env variable is not set")
        return False
    verify = True
    if app.DISABLE_TLS_VALIDATION == "1":
        verify = False
    rules = requests.get(url="{}{}".format(app.UI_HOST,app.RULES_ENDPOINT),verify=verify)
    if not rules.ok:
        logging.warning("Unable to gather rules from {}. Status code: {}. Warning:{}".format(app.UI_HOST,
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

    # get events
    events = requests.get(url="{}{}".format(app.UI_HOST,app.EVENTS_ENDPOINT),verify=verify)
    if not events.ok:
        logging.warning("Unable to gather rules from {}. Status code: {}. Warning:{}".format(app.UI_HOST,
            events.status_code,events.text))
        return False
    for event in events.json():
#haaaaaaa
        logging.debug("Execution event:{} against rules".format(event["uid"]))
        # execute all rules against the event
        hits = execute_event_against_rules(event,logging)
        if hits:
            data.append({"uid":event["uid"],"hits":hits})
    print(data)
    """
    # post results
    results = requests.post(url="{}{}".format(app.UI_HOST,app.RESULTS_ENDPOINT),verify=verify)
    if not results.ok:
        logging.warning("Unable to POST results to {}. Status code: {}. Warning:{}".format(app.UI_HOST,
            results.status_code,results.text))
        return False
    """
