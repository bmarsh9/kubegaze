import os

class Config():
    def __init__(self,base_dir):
        # --------------------------------- Indexer Settings
        self.APP_NAME = os.environ.get("APP_NAME","Indexer")
        self.VERSION = os.environ.get("VERSION","1.0.0")
        self.LOG_LEVEL = os.environ.get("LOG_LEVEL","INFO").upper()
        self.SLEEP_TIME = os.environ.get("SLEEP_TIME",120)

        self.UI_HOST = os.environ.get("UI_HOST")
        self.TOKEN = os.environ.get("TOKEN")
        self.OBJECT_ENDPOINT = os.environ.get("OBJECT_ENDPOINT","/api/v1/cluster/objects")
        self.IGNORE_CERT = os.environ.get("IGNORE_CERT","no")
        self.IN_CLUSTER = os.environ.get("IN_CLUSTER","yes")

        self.TASKS = [
            {"name":"Collect objects from K8 cluster","module":"get_collection","enabled":True},
        ]
