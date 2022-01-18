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
from app.utils.code_template import default_rule_code
import hashlib
import arrow
import json
import os

class Alert(LogMixin,db.Model, UserMixin):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    evidence = db.Column(db.String())
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('rules.id'), nullable=False)
    cluster_id = db.Column(db.Integer, db.ForeignKey('clusters.id'), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

class Rule(LogMixin,db.Model, UserMixin):
    __tablename__ = 'rules'
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(),nullable=False)
    uuid = db.Column(db.String(),nullable=False,unique=True)
    description = db.Column(db.String())
    enabled = db.Column(db.Boolean, default=True)
    hide = db.Column(db.Boolean, default=False)
    severity = db.Column(db.String())
    remediation = db.Column(db.String())
    code = db.Column(db.JSON(),default="{}")
    clusters = db.relationship('Cluster', secondary='assoc_rules', lazy='dynamic')
    tags = db.relationship('Tag', secondary='assoc_rule_tags', lazy='dynamic')
    alerts = db.relationship('Alert', backref='rule', lazy='dynamic')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def get_tags(self,to_list=False):
        tags = []
        for tag in self.tags.all():
            tag = Tag.query.get(tag.id)
            if tag:
                tags.append(tag)
        return tags

    def to_json(self):
        clusters = []
        for cluster in self.clusters.all():
            clusters.append(cluster.id)
        return {
            "id":self.id,
            "uuid":self.uuid,
            "label":self.label,
            "description":self.description,
            "enabled":self.enabled,
            "code":self.code,
            "clusters":clusters,
            "date_added":self.date_added
        }

    def remove_from_all_clusters(self):
        AssocRule.query.filter(AssocRule.rule_id == self.id).delete()
        db.session.commit()
        return True

    def set_clusters_by_id(self,clusters):
        self.remove_from_all_clusters()
        if not isinstance(clusters,list):
            clusters = [clusters]
        for id in clusters:
            found = Cluster.query.get(id)
            if found:
                assoc = AssocRule(rule_id=self.id,cluster_id=id)
                db.session.add(assoc)
        db.session.commit()
        return True

    def remove_from_all_tags(self):
        AssocRuleTag.query.filter(AssocRuleTag.rule_id == self.id).delete()
        db.session.commit()
        return True

    def set_tags_by_name(self,tags,create_if_not=False):
        self.remove_from_all_tags()
        if not isinstance(tags,list):
            tags = [tags]
        for name in tags:
            found = Tag.find_by_name(name)
            if found:
                assoc = AssocRuleTag(rule_id=self.id,tag_id=found.id)
                db.session.add(assoc)
            else:
                if create_if_not:
                    new_tag = Tag(name=name)
                    db.session.add(new_tag)
                    db.session.commit()
                    assoc = AssocRuleTag(rule_id=self.id,tag_id=new_tag.id)
                    db.session.add(assoc)
        db.session.commit()
        return True

    @staticmethod
    def add(uuid=None,label=None,description=None,enabled=True,code={}):
        if not uuid:
            uuid = str(generate_uuid())
        if not label:
            label = str(uuid)
        rule = Rule(uuid=str(uuid),label=label,description=description,enabled=enabled,code=code)
        db.session.add(rule)
        db.session.flush()
        if not code:
            rule.code = default_rule_code(rule.id,name=uuid)
        db.session.commit()
        return rule

    def get_table_for_rule_details(self):
        template = ""
        shell_template = """
                                  <div class="table-responsive rounded-2">
                                    <table class="table table-vcenter">
                                      <thead class="bg-secondary">
                                        <tr>
                                          <th class="w-1 text-white">Key</th>
                                          <th class="text-white">Value</th>
                                        </tr>
                                      </thead>
                                      <tbody>
                                      {}
                                      </tbody>
                                    </table>
                                  </div>
        """
        row_template = """
          <tr>
            <td class="bg-secondary text-white subheader">{}</td>
            <td class="text-white subheader">{}</td>
          </tr>"""
        template+=row_template.format("id",self.id)
        template+=row_template.format("label",self.label)
        template+=row_template.format("severity",self.severity)
        template+=row_template.format("description",self.description)
        template+=row_template.format("remediation",self.remediation)
        return shell_template.format(template)

class Event(LogMixin,db.Model, UserMixin):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String())
    kind = db.Column(db.String(),default="unknown")
    apiversion = db.Column(db.String())
    name = db.Column(db.String(),default="unknown")
    namespace = db.Column(db.String(),default="unknown")
    operation = db.Column(db.String(),default="unknown")
    data = db.Column(db.JSON(),default={})
    tags = db.relationship('Tag', secondary='assoc_tags', lazy='dynamic')
    seen = db.Column(db.Boolean, default=False) # ran against rules
    cluster_id = db.Column(db.Integer, db.ForeignKey('clusters.id'), nullable=False)
    alerts = db.relationship('Alert', backref='event', lazy='dynamic')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def to_json(self):
        tags = []
        for tag in self.tags.all():
            tags.append(tag.name)
        return {
            "id":self.id,
            "uid":self.uid,
            "kind":self.kind,
            "apiversion":self.apiversion,
            "name":self.name,
            "namespace":self.namespace,
            "operation":self.operation,
            "data":self.data,
            "cluster_name":self.cluster.label,
            "tags":tags,
            "date_added":self.date_added
        }

    def has_tags(self,search_tags):
        if not isinstance(search_tags,list):
            search_tags = [search_tags]
        current_tags = self.tags
        for tag in search_tags:
            found = Tag.query.filter(Tag.name == tag.lower()).first()
            if not found:
                return False
            if found not in current_tags:
                return False
        return True

    def remove_from_all_tags(self):
        AssocTag.query.filter(AssocTag.event_id == self.id).delete()
        db.session.commit()
        return True

    def set_tags_by_name(self,tags,as_objects=False,create_if_not=False):
        self.remove_from_all_tags()
        if as_objects:
            self.tags.extend(tags)
            db.session.commit()
        else:
            if not isinstance(tags,list):
                tags = [tags]
            for name in tags:
                found = Tag.find_by_name(name)
                if found:
                    assoc = AssocTag(event_id=self.id,tag_id=found.id)
                    db.session.add(assoc)
                else:
                    if create_if_not:
                        new_tag = Tag(name=name)
                        db.session.add(new_tag)
                        db.session.commit()
                        assoc = AssocTag(event_id=self.id,tag_id=new_tag.id)
                        db.session.add(assoc)
            db.session.commit()
        return True

    def get_table_for_event_details(self):
        template = ""
        row_template = """
          <tr>
            <td class="bg-secondary text-white subheader">{}</td>
            <td class="text-white subheader">{}</td>
            <td>{}</td>
          </tr>"""
        template+=row_template.format("id",self.id,"")
        template+=row_template.format("cluster",self.cluster.label,"")
        template+=row_template.format("Seen by Rules",self.seen,"")
        template+=row_template.format("uid",self.uid,"")
        template+=row_template.format("time",self.date_added,"")
        template+=row_template.format("kind",self.kind,"")
        template+=row_template.format("apiversion",self.apiversion,"")
        template+=row_template.format("name",self.name,"")
        template+=row_template.format("namespace",self.namespace,"")
        template+=row_template.format("operation",self.operation,"")
        alert_link_html = ""
        alerts = self.alerts.count()
        if alerts:
            alert_link_html = '<a href="/events/{}/alerts"><i class="ti ti-external-link text-cyan cursor-pointer"></i></a>'.format(self.id)
        template+=row_template.format("alerts",alerts,alert_link_html)
        return template

    def to_list(self):
        labels_html = """
        """
        for field in ["operation","name"]:
            color = "cyan"
            if field == "operation":
                color = "orange"
            labels_html += '<span class="badge bg-{}-lt mr-2">{}:{}</span>'.format(color,field,getattr(self,field))
        for tag in self.tags.all():
            labels_html += '<span class="badge bg-{}-lt mr-2">{}</span>'.format(tag.color,tag.name)
        seen = ""
        if self.seen:
            seen = "border-start border-info"
        ribbon = ""
        if self.alerts.count():
            ribbon = '<div class="ribbon ribbon-top bg-red"><i style="font-size:1rem" class="ti ti-alert-triangle"></i></div>'
        template = """
              <div class="accordion-item mb-2 bg-dark rounded-2">
                <h2 class="accordion-header {}" id="heading_{}">
                  <button class="accordion-button collapsed text-secondary bg-dark d-block" type="button" data-bs-toggle="collapse" data-bs-target="#event_{}" aria-expanded="false" aria-controls="event_{}">
                    {}<div class="row"><div class="col-1 text-center mt-2"><i style="font-size:2rem" class="ti ti-3d-cube-sphere text-cyan"></i><br><small class="subheader">{}</small></div><div class="col-11"><div class="row"><div class="col-12 mb-2 d-flex align-items-center"><div class="h3" style="color:#a4a3a3;">{} / {}</div><div class="ms-auto subheader mt-3">{}</div></div><div class="col-12">{}</div></div></div></div>
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
                              <div class="card-body scroll">
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
                                      {}
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
              </div>""".format(seen,self.id,self.id,self.id,ribbon,self.id,self.kind,self.name,
                  self.date_added,labels_html,self.id,self.id,self.id,json.dumps(self.data,indent=4),
                  self.get_table_for_event_details())

        return template

    @staticmethod
    def get_operations_in_list():
        operations = []
        for operation in Event.query.with_entities(Event.operation).distinct().all():
          name = str(operation[0]).lower()
          if name not in operations:
              operations.append(name)
        return operations

    @staticmethod
    def get_events_from_api_query(date_added=None,operations=[],tags=[],clusters=[],
        alerts=None,name=None,namespace=None,uid=None,date_sort="gt",last=0,limit=50):
        data = {"last":0,"events":[]}
        _query = Event.query
        if name:
            search = "%{}%".format(name)
            _query = _query.filter(Event.name.ilike(search))
        if namespace:
            search = "%{}%".format(namespace)
            _query = _query.filter(Event.namespace.ilike(search))
        if uid:
            search = "%{}%".format(uid)
            _query = _query.filter(Event.uid.ilike(search))
        if clusters:
            _query = _query.filter(Event.cluster_id.in_(clusters))
        if operations:
            _query = _query.filter(func.lower(Event.operation).in_(operations))
        if tags:
            for tag in tags:
                _query = _query.filter(Event.tags.any(name=tag.lower()))
        if alerts:
            _query = _query.filter(Event.alerts.any())
        if last:
            data["last"] = last
            _query = _query.filter(Event.id > last)
        if date_added:
            dt = arrow.get(date_added).datetime
            if date_sort != "gt":
                _query = _query.filter(Event.date_added <= dt)
            else:
                _query = _query.filter(Event.date_added >= dt)

        events = _query.order_by(Event.id.desc()).limit(limit).all()
        for event in events[::-1]:
            data["events"].append({"id":event.id,"html":event.to_list()})
            if event == events[0]:
                data["last"] = event.id
        return data

class Cluster(LogMixin,db.Model, UserMixin):
    __tablename__ = 'clusters'
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(),nullable=False)
    label = db.Column(db.String(),nullable=False)
    events = db.relationship('Event', backref='cluster', lazy='dynamic')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def get_rules(self):
        rules = []
        for assoc in AssocRule.query.filter(AssocRule.cluster_id == self.id).all():
            rules.append(Rule.query.get(assoc.rule_id))
        return rules

    def get_alerts(self):
        return Alert.query.filter(Alert.cluster_id == self.id).all()

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
        if data.get("type") == "cluster":
            return True
        return False

    @staticmethod
    def generate_auth_token():
        s = Serializer(current_app.config['SECRET_KEY'])
        token = s.dumps({"type":"cluster"})
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

class AssocRule(LogMixin,db.Model):
    __tablename__ = 'assoc_rules'
    id = db.Column(db.Integer(), primary_key=True)
    rule_id = db.Column(db.Integer(), db.ForeignKey('rules.id', ondelete='CASCADE'))
    cluster_id = db.Column(db.Integer(), db.ForeignKey('clusters.id', ondelete='CASCADE'))

class AssocRuleTag(LogMixin,db.Model):
    __tablename__ = 'assoc_rule_tags'
    id = db.Column(db.Integer(), primary_key=True)
    tag_id = db.Column(db.Integer(), db.ForeignKey('tags.id', ondelete='CASCADE'))
    rule_id = db.Column(db.Integer(), db.ForeignKey('rules.id', ondelete='CASCADE'))

class AssocTag(LogMixin,db.Model):
    __tablename__ = 'assoc_tags'
    id = db.Column(db.Integer(), primary_key=True)
    tag_id = db.Column(db.Integer(), db.ForeignKey('tags.id', ondelete='CASCADE'))
    event_id = db.Column(db.Integer(), db.ForeignKey('events.id', ondelete='CASCADE'))

class Tag(LogMixin,db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(), unique=True)
    color = db.Column(db.String(), default="blue")
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    @staticmethod
    def find_by_name(name):
        tag_exists = Tag.query.filter(func.lower(Tag.name) == func.lower(name)).first()
        if tag_exists:
            return tag_exists
        return False

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
