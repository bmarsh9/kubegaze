from flask import jsonify, request, current_app
from . import api
from app.models import *
from flask_login import login_required
import arrow

@api.route('/graph/cluster-event-count', methods=['GET'])
@login_required
def graph_get_cluster_event_count():
    series = []
    labels = []
    now = arrow.utcnow()
    for cluster in Cluster.query.all():
        labels.append("{}...".format(cluster.label[:7]))
        series.append(Event.query.filter(Event.date_added >= now.shift(hours=-24).datetime).filter(Event.cluster_id == cluster.id).count())
    return jsonify({"labels":labels,"series":series})

@api.route('/graph/alerts-by-severity', methods=['GET'])
@login_required
def graph_get_alerts_by_severity():
    span_of_days = [(0,7),(7,14),(14,21),(21,28),(28,35)]
    now = arrow.utcnow()
    categories = []
    data = {"low":[],"moderate":[],"high":[]}
    for span in span_of_days:
        start,end = span
        categories.append("{}-{} days ago".format(start,end))
        for severity in ["low","moderate","high"]:
            count = Alert.query.filter(Alert.date_added < now.shift(days=-start).datetime).filter(Alert.date_added > now.shift(days=-end).datetime).join(Rule).filter(Rule.severity == severity).count()
            data[severity].append(count)
    series = []
    for key,value in data.items():
        series.append({"name":key.upper(),"data":value})
    return jsonify({"categories":categories,"series":series})

@api.route("/graphs/events", methods=["GET"])
@login_required
def graph_get_events():
    data = {"data":[]}
    now = arrow.utcnow()
    for log in Logs.query.filter(Logs.date_added > now.shift(days=-7).datetime).order_by(Logs.id.desc()).all():
        data["data"].append([log.id,log.log_type,log.message,log.date_added])
    return jsonify(data)
