import os

class Config():
    def __init__(self,base_dir):
        # --------------------------------- Poller Settings
        self.APP_NAME = os.environ.get("APP_NAME","Poller")
        self.VERSION = os.environ.get("VERSION","1.0.0")
        self.LOG_LEVEL = os.environ.get("LOG_LEVEL","INFO").upper()
        self.SLEEP_TIME = os.environ.get("SLEEP_TIME",120)

        self.UI_HOST = os.environ.get("UI_HOST")
        self.RULES_ENDPOINT = os.environ.get("RULES_ENDPOINT","/api/v1/rules")
        self.EVENTS_ENDPOINT = os.environ.get("EVENTS_ENDPOINT","/api/v1/events")
        self.RESULTS_ENDPOINT = os.environ.get("RESULTS_ENDPOINT","/api/v1/hits")
        self.DISABLE_TLS_VALIDATION = os.environ.get("DISABLE_TLS_VALIDATION","0")

        self.TASKS = [
            {"name":"Save the rules from the UI","module":"get_rules","enabled":True},
            {"name":"Execute rules against the events","module":"execute_rules","enabled":True},
        ]
