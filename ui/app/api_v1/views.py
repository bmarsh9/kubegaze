from flask import jsonify, request, current_app
from . import api
from app.models import *
from flask_login import login_required
from app.utils.decorators import roles_required,cluster_auth
from app.utils.misc import generate_uuid
from datetime import datetime, timedelta

@api.route('/health', methods=['GET'])
def get_health():
    return jsonify({"message":"ok"})

@api.route('/clusters/<int:id>/token', methods=['GET'])
@login_required
def get_token_for_cluster(id):
    cluster = Cluster.query.get(id)
    if not cluster:
        return jsonify({"message":"cluster not found"}),404
    token = cluster.generate_auth_token()
    return jsonify({"token":token})

@api.route('/cluster/<int:id>/events', methods=['POST'])
#@cluster_auth
def post_events_from_cluster(id):
    cluster = Cluster.query.get(id)
    if not cluster:
        return jsonify({"message":"cluster not found"}),404
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
    return jsonify({"message":"ok"})

@api.route('/events', methods=['GET'])
@login_required
def get_events():
    #haaaa
    date_added = request.args.get('date_added', None, type=str)
    if not date_added:
        date_added = datetime.now() - timedelta(hours = 24)
    events = Event.get_events_from_api_query(
        name=request.args.get('name', None, type=str),
        namespace=request.args.get('namespace', None, type=str),
        operations=request.args.getlist('operations'),
        tags=request.args.getlist('tags'),
        date_sort=request.args.get('date_sort', "gt", type=str),
        date_added=date_added,
        last=request.args.get('last', 0, type=int),
        limit=request.args.get('limit', 50, type=int),
    )
    return jsonify(events)

@api.route('/rules/<int:id>/code', methods=['GET'])
def get_code_for_rule(id):
    rule = Rule.query.get(id)
    return jsonify({"code":rule.code})

@api.route('/rules/<int:id>/code', methods=['PUT'])
def save_code_for_rule(id):
    rule = Rule.query.get(id)
    data = request.get_json()
    rule.code = data["code"]
    db.session.commit()
    return jsonify({"code":rule.code})
