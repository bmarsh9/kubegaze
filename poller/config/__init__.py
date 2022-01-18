from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session
import sqlalchemy
import os
import docker

db = automap_base()

class Config():
    def __init__(self,base_dir):
        # --------------------------------- Poller Setting
        self.APP_NAME = os.environ.get("APP_NAME","Poller")
        self.UI_HOST = os.environ.get("UI_HOST")
        self.VERSION = os.environ.get("VERSION","1.0.0")
        self.LOG_LEVEL = os.environ.get("LOG_LEVEL","DEBUG")
        self.SLEEP_TIME = os.environ.get("SLEEP_TIME",120)

        self.TASKS = [
            {"name":"Remove stale workflow containers","module":"remove_stale_workflow_containers","enabled":True},
            {"name":"Send notification email for paused paths","module":"send_email_for_paused_path","enabled":True},
        ]
