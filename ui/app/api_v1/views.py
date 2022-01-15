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
def get_events_from_cluster(id):
    cluster = Cluster.query.get(id)
    if not cluster:
        return jsonify({"message":"cluster not found"}),404
    data = request.get_json()
    print(data)
    return jsonify({"message":"ok"})
