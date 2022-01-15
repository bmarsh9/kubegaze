from flask import current_app
from flask_script import Command
from app.models import *
from app import db
import datetime

class InitDbCommand(Command):
    """ Initialize the database."""

    def run(self):
        init_db()
        print('Database has been initialized.')

def init_db():
    """ Initialize the database."""
    db.drop_all()
    db.create_all()
    create_users()
    create_default_cluster()

def create_users():
    """ Create users """
    default_user = current_app.config.get("DEFAULT_EMAIL","admin@example.com")
    default_password = current_app.config.get("DEFAULT_PASSWORD","admin")
    if not User.query.filter(User.email == default_user).first():
        user = User(
            email=default_user,
            email_confirmed_at=datetime.datetime.utcnow(),
        )
        user.set_password(default_password)
        user.roles.append(Role(name='Admin'))
        user.roles.append(Role(name='User'))
        db.session.add(user)
        db.session.commit()

def create_default_cluster():
    if not Cluster.query.first():
        Cluster.add()
    return
