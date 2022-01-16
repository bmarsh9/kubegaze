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
    cluster.events.append(Event(data=request.get_json()))
    db.session.commit()
    return jsonify({"message":"ok"})

@api.route('/events', methods=['GET'])
@login_required
def get_events():
    since = request.args.get('since', 100, type=int)
    latest = request.args.get('latest', 1, type=int)

    data = {
        "last":request.args.get('last', 0, type=int),
        "events":[]
    }
    _query = Event.query
    if latest:
        flip=True
        _query = _query.order_by(Event.id.desc())
    else:
        flip=False
        from_date = datetime.now() - timedelta(minutes=since)
        _query = _query.filter(Event.date_added >= from_date)
    if data["last"]:
        _query = _query.filter(Event.id > data["last"])

    events = _query.limit(request.args.get("limit",50)).all()
    if flip:
        events = events[::-1]
    for event in events:
        data["events"].append({"id":event.id,"html":event.to_list()})
        if event  == events[-1]: #last element
            data["last"] = event.id
    return jsonify(data)
