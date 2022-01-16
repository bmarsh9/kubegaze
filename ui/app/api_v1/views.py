from flask import jsonify, request, current_app
from . import api
from app.models import *
from flask_login import login_required
from app.utils.decorators import roles_required,cluster_auth
from app.utils.misc import generate_uuid

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
    cluster.events.append(Event(data=request.get_json()))
    db.session.commit()
    return jsonify({"message":"ok"})

@api.route('/events', methods=['GET'])
#@cluster_auth
def get_events():
    data = {"current":0,"next":0,"events":[]}
#    data = []
    current = request.args.get('current', 0, type=int)
    next = request.args.get('next', 0, type=int)

    _query = Event.query
    if next:
        _query = _query.filter(Event.id > next)
    events = _query.limit(request.args.get("limit",100))

    for event in events:
#    for event in Event.query.filter(Event.id.between(5,10)).order_by(Event.id.desc()).limit(request.args.get("limit",10)):
#    for event in Event.query.paginate(page=page, per_page=10).items:
        data["events"].append({"id":event.id,"html":event.to_list()})
        if event  == events[-1]: #last element
            data["next"] = event.id
    return jsonify(data)
