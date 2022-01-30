import requests
import os
import json
from utils import helpers
from kubernetes import client, config, watch

def get_collection(app, logging):
    # check env configs
    if not app.UI_HOST:
        logging.error("UI_HOST env variable is not set")
        return False
    if not app.TOKEN:
        logging.error("Token env variable is not set")
    if app.IN_CLUSTER == "yes":
        logging.debug("Loading in cluster config")
        config.load_incluster_config()
    else:
        logging.debug("Loading Kube config file (out of cluster)")
        config.load_kube_config()
    verify = True
    if app.IGNORE_CERT == "yes":
        verify = False

    # collect data from cluster
    resources = [
        {"AppsV1Api":"list_daemon_set_for_all_namespaces"},
        {"AppsV1Api":"list_deployment_for_all_namespaces"},
        {"AppsV1Api":"list_replica_set_for_all_namespaces"},
        {"AppsV1Api":"list_stateful_set_for_all_namespaces"},
        {"BatchV1Api":"list_cron_job_for_all_namespaces"},
        {"BatchV1Api":"list_job_for_all_namespaces"},
        {"CoreV1Api":"list_config_map_for_all_namespaces"},
        {"CoreV1Api":"list_endpoints_for_all_namespaces"},
        {"CoreV1Api":"list_event_for_all_namespaces"},
        {"CoreV1Api":"list_pod_for_all_namespaces"},
        {"CoreV1Api":"list_secret_for_all_namespaces"},
        {"CoreV1Api":"list_service_account_for_all_namespaces"},
        {"CoreV1Api":"list_service_for_all_namespaces"},
        {"NetworkingV1Api":"list_ingress_for_all_namespaces"},
        {"NetworkingV1Api":"list_network_policy_for_all_namespaces"},
        {"RbacAuthorizationV1Api":"list_role_binding_for_all_namespaces"},
        {"RbacAuthorizationV1Api":"list_role_for_all_namespaces"},
    ]
    objects_url = "{}{}".format(app.UI_HOST,app.OBJECT_ENDPOINT)
    logging.debug("Sending collection to {}".format(objects_url))

    for resource in resources:
        for _class,_method in resource.items():
            logging.debug("Collecting {}".format(_method))
            v1 = getattr(client,_class)()
            results = getattr(v1,_method)()
            logging.debug("Collected {} results for {}".format(len(results.items),_method))
            data = {
                "category":_method,
                "results":results.items
            }
            # send data to UI server
            objects = requests.post(url=objects_url,json=data,verify=verify,headers={"token":app.TOKEN})
            if not objects.ok:
                logging.warning("Unable to send collection results to {}. Status code: {}. Warning:{}".format(objects_url,
                    objects.status_code,objects.text))
            else:
                logging.debug("Successfully uploaded {} results for {}".format(len(results.items),_method)
    return True
