from kubernetes import client, config
import json

class K8Indexer():
    def __init__(self,in_cluster=True):
        if in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config()
        self.client = client

    def get_all(self,list_of_methods=[],dump=True):
        data = []
        if not list_of_methods:
            list_of_methods = ["get_nodes","get_namespaces","get_pods",
                "get_daemon_sets","get_deployments",
                "get_replica_sets","get_stateful_sets","get_cron_jobs",
                "get_jobs","get_config_maps","get_endpoints",
                "get_secrets","get_svc_accounts","get_role_bindings","get_roles",
                "get_services","get_ingress","get_network_policies"
            ]
        for method in list_of_methods:
            results = getattr(self,method)()
            if results:
                if dump:
                    data.append(json.dumps({"operation":method,"results":results},default=str))
                else:
                    data.append({"operation":method,"results":results})
        return data

    # Core
    def get_nodes(self):
        data = []
        v1 = self.client.CoreV1Api()
        results = v1.list_node()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"node","data":record})
        return data

    def get_namespaces(self):
        data = []
        v1 = self.client.CoreV1Api()
        results = v1.list_namespace()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["name"],"kind":"namespace","data":record})
        return data

    def get_pods(self):
        data = []
        v1 = self.client.CoreV1Api()
        results = v1.list_pod_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"pod","data":record})
        return data

    def get_containers(self):
        containers = self.get_pods()

    # Apps
    def get_daemon_sets(self):
        data = []
        v1 = self.client.AppsV1Api()
        results = v1.list_daemon_set_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"daemon_set","data":record})
        return data

    def get_deployments(self):
        data = []
        v1 = self.client.AppsV1Api()
        results = v1.list_deployment_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"deployment","data":record})
        return data

    def get_replica_sets(self):
        data = []
        v1 = self.client.AppsV1Api()
        results = v1.list_replica_set_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"replica_set","data":record})
        return data

    def get_stateful_sets(self):
        data = []
        v1 = self.client.AppsV1Api()
        results = v1.list_stateful_set_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"stateful_set","data":record})
        return data

    def get_cron_jobs(self):
        data = []
        v1 = self.client.BatchV1Api()
        results = v1.list_cron_job_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"cron_job","data":record})
        return data

    def get_jobs(self):
        data = []
        v1 = self.client.BatchV1Api()
        results = v1.list_job_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"job","data":record})
        return data

    def get_config_maps(self):
        data = []
        v1 = self.client.CoreV1Api()
        results = v1.list_config_map_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"config_map","data":record})
        return data

    def get_endpoints(self):
        data = []
        v1 = self.client.CoreV1Api()
        results = v1.list_endpoints_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"endpoint","data":record})
        return data

    def get_events(self):
        data = []
        v1 = self.client.CoreV1Api()
        results = v1.list_event_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"event","data":record})
        return data

    # Rbac
    def get_secrets(self):
        data = []
        v1 = self.client.CoreV1Api()
        results = v1.list_secret_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"secret","data":record})
        return data

    def get_svc_accounts(self):
        data = []
        v1 = self.client.CoreV1Api()
        results = v1.list_service_account_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"service_account","data":record})
        return data

    def get_role_bindings(self):
        data = []
        v1 = self.client.RbacAuthorizationV1Api()
        results = v1.list_role_binding_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"role_binding","data":record})
        return data

    def get_roles(self):
        data = []
        v1 = self.client.RbacAuthorizationV1Api()
        results = v1.list_role_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"role","data":record})
        return data

    # Networking
    def get_services(self):
        data = []
        v1 = self.client.CoreV1Api()
        results = v1.list_service_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"service","data":record})
        return data

    def get_ingress(self):
        data = []
        v1 = self.client.NetworkingV1Api()
        results = v1.list_ingress_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"ingress","data":record})
        return data

    def get_network_policies(self):
        data = []
        v1 = self.client.NetworkingV1Api()
        results = v1.list_network_policy_for_all_namespaces()
        for record in results.to_dict()["items"]:
            data.append({"name":record["metadata"]["name"],"uid":record["metadata"]["uid"],
                "namespace":record["metadata"]["namespace"],"kind":"network_policy","data":record})
        return data
