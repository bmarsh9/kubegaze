from flask import jsonify, request, current_app
from . import api
from app.models import *
from flask_login import login_required
from app.utils.decorators import roles_required,cluster_auth,poller_auth
from app.utils.misc import generate_uuid
from datetime import datetime, timedelta
import json

@api.route('/health', methods=['GET'])
def get_health():
    return jsonify({"message":"ok"})

@api.route('/clusters/token/check', methods=['GET'])
def check_token_for_cluster():
    token = request.args.get("token")
    if not token:
        return jsonify({"message":"token not found in request args"}),400
    cluster = Cluster.verify_auth_token(token)
    if not cluster:
        return jsonify({"message":"authentication failed"}),401
    return jsonify({"message":"ok","cluster":cluster.label,"uuid":cluster.uuid})

@api.route('/poller/token/check', methods=['GET'])
def check_token_for_poller():
    token = request.args.get("token")
    if not token:
        return jsonify({"message":"token not found in request args"}),400
    poller = Cluster.verify_poller_token(token)
    if not poller:
        return jsonify({"message":"authentication failed"}),401
    return jsonify({"message":"ok"})

@api.route('/clusters/<int:id>/token', methods=['GET'])
@login_required
def get_token_for_cluster(id):
    cluster = Cluster.query.get(id)
    return jsonify({"token":cluster.generate_auth_token()})

@api.route('/cluster/objects', methods=['POST'])
@cluster_auth
def post_objects_from_cluster(cluster=None):
    if current_app.config["DISABLE_CLUSTER_AUTH"] == "yes":
        cluster = Cluster.query.get(request.args.get("cluster_id",0))
        if not cluster:
            return jsonify({"message":"cluster not found. cluster authentication is disabled"}),404
    cluster = Cluster.query.get(1)
    data = json.loads(request.get_json())
    for result in data:
        exists = Object.query.filter(Object.uid == result["uid"]).first()
        if not exists:
            object = Object(uid=result["uid"],kind=result["kind"],name=result["name"],
                namespace=result["namespace"],data=result["data"])
            cluster.objects.append(object)
        else:
            exists.data = result["data"]
    db.session.commit()
    return jsonify({"message":"ok"})

@api.route('/cluster/events', methods=['POST'])
@cluster_auth
def post_events_from_cluster(cluster=None):
    if current_app.config["DISABLE_CLUSTER_AUTH"] == "yes":
        cluster = Cluster.query.get(request.args.get("cluster_id",0))
        if not cluster:
            return jsonify({"message":"cluster not found. cluster authentication is disabled"}),404
    data = request.get_json()
    event = Event(uid=data["request"]["uid"],
        apiversion=data["apiVersion"],
        kind=data["request"]["kind"]["kind"],
        name=data["request"].get("name"),
        namespace=data["request"].get("namespace"),
        operation=data["request"].get("operation"),
        data=data
    )
    cluster.events.append(event)
    db.session.commit()
    return jsonify(
        {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "allowed": True,
                "uid": request.json["request"]["uid"],
                "status": {"message": "ok"},
            }
        }
    )

@api.route('/feed', methods=['GET'])
@login_required
def get_event_feed():
    date_added = request.args.get('date_added', None, type=str)
    if not date_added:
        date_added = datetime.now() - timedelta(hours = 24)
    events = Event.get_events_from_api_query(
        name=request.args.get('name', None, type=str),
        namespace=request.args.get('namespace', None, type=str),
        uid=request.args.get('uid', None, type=str),
        clusters=request.args.getlist('clusters'),
        operations=request.args.getlist('operations'),
        tags=request.args.getlist('tags'),
        date_sort=request.args.get('date_sort', "gt", type=str),
        date_added=date_added,
        last=request.args.get('last', 0, type=int),
        alerts=int(request.args.get('alerts', 0, type=int)),
        limit=request.args.get('limit', 50, type=int),
    )
    return jsonify(events)

@api.route('/rules/<int:id>/code', methods=['GET'])
@login_required
def get_code_for_rule(id):
    rule = Rule.query.get(id)
    return jsonify({"code":rule.code})

@api.route('/rules/<int:id>/code', methods=['PUT'])
@login_required
def save_code_for_rule(id):
    rule = Rule.query.get(id)
    data = request.get_json()
    rule.code = data["code"]
    db.session.commit()
    return jsonify({"code":rule.code})

@api.route('/tags/<int:id>/color/<string:color>', methods=['PUT'])
@login_required
def update_color_for_tag(id,color):
    tag = Tag.query.get(id)
    tag.color = color
    db.session.commit()
    return jsonify({"message":"ok"})

@api.route('/rules', methods=['GET'])
@poller_auth
def get_rules():
    data = []
    for rule in Rule.query.filter(Rule.hide == False).filter(Rule.enabled == True).all():
        data.append(rule.to_json())
    return jsonify(data)

@api.route('/events', methods=['GET'])
@poller_auth
def get_events():
    data = []
    for event in Event.query.filter(Event.seen == False).order_by(Event.id.desc()).limit(100).all():
        data.append(event.to_json())
    return jsonify(data)

@api.route('/hits', methods=['POST'])
@poller_auth
def post_hits():
    data = request.get_json()
    for record in data:
        event = Event.query.get(record["id"])
        if event:
            event.seen = True
            for alert in record["hits"]:
                rule = Rule.query.get(alert["rule_id"])
                if rule:
                    event.set_tags_by_name(rule.tags.all(),as_objects=True)
                    event.alerts.append(Alert(evidence=alert["evidence"],
                        rule_id=alert["rule_id"],cluster_id=event.cluster_id))
    db.session.commit()
    return jsonify({"message":"ok"})

@api.route('/clusters/<int:id>/graph', methods=['GET'])
@login_required
def get_graph(id):
    cluster = Cluster.query.get(id)
    return jsonify(cluster.to_graph_format())

@api.route("/objects", methods=["GET"])
@login_required
def get_objects():
    objects = Object.get_objects_from_api_query(
        clusters=request.args.getlist('clusters'),
        kinds=request.args.getlist('kinds'),
    )
    return jsonify({"data":objects})
