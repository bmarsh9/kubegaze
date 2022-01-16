from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy import func,and_,or_
from app.utils.mixin_models import LogMixin
from flask_login import UserMixin
from app.utils.misc import generate_uuid
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from datetime import datetime
from app.email import send_email
from app import db, login
import hashlib
import arrow
import json
import os

class Event(LogMixin,db.Model, UserMixin):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String())
    kind = db.Column(db.String())
    data = db.Column(db.JSON(),default={})
    cluster_id = db.Column(db.Integer, db.ForeignKey('clusters.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def to_list(self):
        labels_html = """
        """
        for i in range(0,5):
            labels_html += '<span class="badge bg-cyan-lt mr-2">badge {}</span>'.format(i)
        template = """
              <div class="accordion-item mb-2 bg-dark rounded-2">
                <h2 class="accordion-header" id="heading_{}">
                  <button class="accordion-button collapsed text-secondary bg-dark d-block" type="button" data-bs-toggle="collapse" data-bs-target="#event_{}" aria-expanded="false" aria-controls="event_{}">
                    <div class="row"><div class="col-1 text-center mt-2"><i style="font-size:2rem" class="ti ti-3d-cube-sphere"></i></div><div class="col-11"><div class="row"><div class="col-12 mb-2 d-flex align-items-center"><div class="h3">{}</div><div class="ms-auto subheader">{}</div></div><div class="col-12">{}</div></div></div></div>
                  </button>
                </h2>
                <div id="event_{}" class="accordion-collapse collapse" aria-labelledby="heading_{}" data-bs-parent="#event_{}">
                  <div class="accordion-body text-secondary border-wide">
                    <div class="card-body">
                      <div class="row">
                        <div class="col-6">
                          <div class="card bg-light">
                              <div class="card-header">
                                <h3 class="card-title">Event Spec</h3>
                                <div class="card-actions"><i class="ti ti-apple icon"></i></div>
                              </div>
                              <div class="card-body">
                                <pre>{}</pre>
                              </div>
                          </div>
                        </div>
                        <div class="col-6">
                          <div class="card bg-dark">
                              <div class="card-header">
                                <h3 class="card-title text-cyan">Details</h3>
                                <div class="card-actions"><i class="ti ti-notes icon"></i></div>
                              </div>
                              <div class="card-body">
                                  <div class="table-responsive rounded-2">
                                    <table class="table table-vcenter">
                                      <thead class="bg-secondary">
                                        <tr>
                                          <th class="w-1 text-white">Key</th>
                                          <th class="text-white">Value</th>
                                          <th class="w-1"><i class="ti ti-external-link text-white"></i></th>
                                        </tr>
                                      </thead>
                                      <tbody>
                                        <tr>
                                          <td class="bg-secondary text-white subheader">Added</td>
                                          <td class="text-muted subheader">
                                            test
                                          </td>
                                          <td></td>
                                        </tr>
                                        <tr>
                                          <td class="bg-secondary text-white subheader">Kind</td>
                                          <td class="text-muted subheader">
                                            test
                                          </td>
                                          <td></td>
                                        </tr>
                                      </tbody>
                                    </table>
                                  </div>
                              </div>
                          </div>
                        </div>
                      </div>
                    </div>
                    <div class="card-footer bg-transparent">
                    </div>
                  </div>
                </div>
              </div>""".format(self.id,self.id,self.id,self.kind,self.date_added,labels_html,self.id,self.id,self.id,self.data)

        return template

class Cluster(LogMixin,db.Model, UserMixin):
    __tablename__ = 'clusters'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(),nullable=False)
    label = db.Column(db.String(),nullable=False)
    events = db.relationship('Event', backref='cluster', lazy='dynamic')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @staticmethod
    def add(**kwargs):
        uuid = generate_uuid()
        kwargs["uuid"] = uuid
        if not kwargs.get("label"):
            kwargs["label"] = "Cluster_{}".format(uuid)
        cluster = Cluster(**kwargs)
        db.session.add(cluster)
        db.session.commit()
        return cluster

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            current_app.logger.warning("SignatureExpired for token")
            return None # valid token, but expired
        except BadSignature:
            current_app.logger.warning("BadSignature for token")
            return None # invalid token
        return Cluster.query.filter(Cluster.uuid == data["uuid"]).first()

    def generate_auth_token(self):
        s = Serializer(current_app.config['SECRET_KEY'])
        token = s.dumps({ 'id': self.id, 'uuid': self.uuid })
        return token.decode("utf-8")

class User(LogMixin,db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    is_active = db.Column(db.Boolean(), nullable=False, server_default='1')
    email = db.Column(db.String(255), nullable=False, unique=True)
    username = db.Column(db.String(100), unique=True)
    email_confirmed_at = db.Column(db.DateTime())
    password = db.Column(db.String(255), nullable=False, server_default='')
    last_password_change = db.Column(db.DateTime())
    first_name = db.Column(db.String(100), nullable=False, server_default='')
    last_name = db.Column(db.String(100), nullable=False, server_default='')
    roles = db.relationship('Role', secondary='user_roles')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            current_app.logger.warning("SignatureExpired for token")
            return None # valid token, but expired
        except BadSignature:
            current_app.logger.warning("BadSignature for token")
            return None # invalid token
        user = User.query.get(data['id'])
        return user

    def generate_auth_token(self, expiration = 6000):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'id': self.id })

    @staticmethod
    def verify_invite_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            current_app.logger.warning("SignatureExpired for token")
            return None # valid token, but expired
        except BadSignature:
            current_app.logger.warning("BadSignature for token")
            return None # invalid token
        return data["email"]

    @staticmethod
    def generate_invite_token(email,expiration = 600):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'email': email }).decode('utf-8')

    def pretty_roles(self):
        data = []
        for role in self.roles:
            data.append(role.name.lower())
        return data

    def can_edit_roles(self):
        return "admin" in self.pretty_roles()

    def has_role(self,roles):
        '''checks if user has any of the listed roles'''
        if not roles:
            return False
        if not isinstance(roles,list) and not isinstance(roles,tuple):
            roles = [roles]
        my_roles = self.pretty_roles()
        for role in roles:
            if role.lower() in my_roles:
                return True
        return False

    def has_roles(self,roles):
        '''checks if user has all of the listed roles'''
        if not roles:
            return False
        if not isinstance(roles,list) and not isinstance(roles,tuple):
            roles = [roles]
        my_roles = self.pretty_roles()
        for role in roles:
            if role.lower() not in my_roles:
                return False
        return True

    def set_roles_by_name(self,roles):
        #roles = ["Admin","Another Role"]
        if not isinstance(roles,list):
            roles = [roles]
        new_roles = []
        for role in roles:
            found = Role.find_by_name(role)
            if found:
                new_roles.append(found)
        self.roles[:] = new_roles
        db.session.commit()
        return True

    def get_roles_for_form(self):
        roles = {}
        for role in Role.query.all():
            if role in self.roles:
                roles[role] = True
            else:
                roles[role] = False
        return roles

    def is_privileged(self):
        if self.has_role(["admin"]):
            return True
        return False

    def set_password(self, password):
        self.password = generate_password_hash(password, method='sha256')
        self.last_password_change = str(datetime.utcnow())

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Define the Role data-model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)

    @staticmethod
    def find_by_name(name):
        role_exists = Role.query.filter(func.lower(Role.name) == func.lower(name)).first()
        if role_exists:
            return role_exists
        return False

# Define the UserRoles association table
class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

class Tag(LogMixin,db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(), unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ConfigStore(db.Model,LogMixin):
    __tablename__ = 'config_store'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    name = db.Column(db.String(),nullable=False)
    object_store = db.Column(db.JSON(),default={})
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @staticmethod
    def find_by_name(name):
        store_exists = ConfigStore.query.filter(func.lower(ConfigStore.name) == func.lower(name)).first()
        if store_exists:
            return store_exists
        return False

    def get(self,key):
        '''ConfigStore.get("mykey")'''
        return self.object_store.get(key.lower())

    def insert(self,object):
        '''ConfigStore.insert({"mykey":"myvalue"})'''
        if not isinstance(object,dict):
            return False,"Object must be a dictionary"
        temp = {**{},**self.object_store}
        for key,value in object.items():
            key = key.lower()
            temp[key] = value
        self.object_store = temp
        db.session.commit()
        return True

class Logs(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    namespace = db.Column(db.String(),nullable=False,default="general")
    log_type = db.Column(db.String(),nullable=False,default="info")
    message = db.Column(db.String(),nullable=False)
    meta = db.Column(db.JSON(),default="[]")
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    @staticmethod
    def add_log(message,log_type="info",namespace="general",meta={}):
        if log_type.lower() not in ["info","warning","error","critical"]:
            return False
        msg = Logs(namespace=namespace.lower(),message=message,
            log_type=log_type.lower(),meta=meta)
        db.session.add(msg)
        db.session.commit()
        return True

    @staticmethod
    def get_logs(log_type=None,limit=100,as_query=False,span=None,as_count=False,paginate=False,page=1,namespace="general",meta={}):
        '''
        get_logs(log_type='error',namespace="my_namespace",meta={"key":"value":"key2":"value2"})
        '''
        _query = Logs.query.filter(Logs.namespace == namespace.lower()).order_by(Logs.id.desc())
        if log_type:
            if not isinstance(log_type,list):
                log_type = [log_type]
            _query = _query.filter(Logs.log_type.in_(log_type))

        if meta:
            for key,value in meta.items():
                _query = _query.filter(Logs.meta.op('->>')(key) == value)
        if span:
            _query = _query.filter(Logs.date_added >= arrow.utcnow().shift(hours=-span).datetime)
        if as_query:
            return _query
        if as_count:
            return _query.count()
        if paginate:
            return _query.paginate(page=page, per_page=10)
        return _query.limit(limit).all()

@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
