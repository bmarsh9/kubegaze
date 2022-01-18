import importlib
import requests
import os
import glob
import json
import timeout_decorator

@timeout_decorator.timeout(5)
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

