import requests
import os
import json
from utils import helpers
from utils.k8_indexer import K8Indexer
from kubernetes import client, config

def get_collection(app, logging):
    # check env configs
    if not app.UI_HOST:
        logging.error("UI_HOST env variable is not set")
        return False
    if not app.TOKEN:
        logging.error("Token env variable is not set")
    if app.IN_CLUSTER == "yes":
        logging.debug("Loading in cluster config")
        in_cluster = True
    else:
        logging.debug("Loading Kube config file (out of cluster)")
        in_cluster = False
    verify = True
    if app.IGNORE_CERT == "yes":
        verify = False

    objects_url = "{}{}".format(app.UI_HOST,app.OBJECT_ENDPOINT)
    logging.debug("Sending collection to {}".format(objects_url))

    collections = K8Indexer(in_cluster=in_cluster).get_all(dump=False)
    for collection in collections:
        num_of_records = len(collection["results"])
        logging.debug("Collected {} results for {}".format(num_of_records,collection["operation"]))
        # send data to UI server
        request = requests.post(url=objects_url,json=json.dumps(collection["results"],default=str),verify=verify,headers={"token":app.TOKEN})
        if not request.ok:
            logging.warning("Unable to send collection results to {}. Status code: {}. Warning:{}".format(objects_url,
                request.status_code,request.text))
        else:
            logging.debug("Successfully uploaded results for {}".format(collection["operation"]))
    return True
