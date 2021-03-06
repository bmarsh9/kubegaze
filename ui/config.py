import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    #SERVER_NAME = "localhost"
    APP_NAME = os.environ.get("APP_NAME","KubeGaze")
    APP_SUBTITLE = os.environ.get("APP_SUBTITLE","Security monitoring tool for Kubernetes")
    CR_YEAR = os.environ.get("CR_YEAR","2021")
    VERSION = os.environ.get("VERSION","1.0.0")

    LOG_TYPE = os.environ.get("LOG_TYPE", "stream")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING")

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'newllkjlreagjeraihgeorvhlkenvol3u4og98u4g893u4g0u3409u34add'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_DEBUG = os.environ.get('MAIL_DEBUG',False)
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    BASE_DIR = basedir
    ENABLE_SELF_REGISTRATION = os.environ.get("ENABLE_SELF_REGISTRATION",False)
    DOC_LINK = os.environ.get("DOC_LINK","/")
    DEPLOYMENT_LINK = os.environ.get("DEPLOYMENT_LINK","/")

    DEFAULT_EMAIL = os.environ.get("DEFAULT_EMAIL", "admin@example.com")
    DEFAULT_PASSWORD = os.environ.get("DEFAULT_PASSWORD", "admin")

    DISABLE_CLUSTER_AUTH = os.environ.get("DISABLE_CLUSTER_AUTH", "no")
    DISABLE_POLLER_AUTH = os.environ.get("DISABLE_POLLER_AUTH", "no")

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URL') or \
        "postgresql://db1:db1@postgres_db/db1"

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URL') or \
        "postgresql://db1:db1@postgres_db/db1"
    WTF_CSRF_ENABLED = False

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
