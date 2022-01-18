from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, jsonify
from . import main
from app.models import *
from flask_login import login_required,current_user
from app.utils.decorators import roles_required,roles_accepted
from app.utils.misc import generate_uuid
from datetime import datetime, timedelta

@main.route('/', methods=['GET'])
@login_required
def home():
    return render_template("dashboard.html")

@main.route('/clusters', methods=['GET'])
@login_required
def clusters():
    clusters = Cluster.query.all()
    return render_template("clusters.html",clusters=clusters)

@main.route('/clusters/<int:id>', methods=['GET'])
@login_required
def view_cluster(id):
    cluster = Cluster.query.get(id)
    return render_template("view_cluster.html",cluster=cluster)

@main.route('/tags', methods=['GET'])
@login_required
def tags():
    tags = Tag.query.all()
    return render_template("tags.html",tags=tags)

@main.route('/rules', methods=['GET'])
@login_required
def rules():
    rules = Rule.query.all()
    return render_template("rules.html",rules=rules)

@main.route('/rules/<int:id>', methods=['GET'])
@login_required
def view_rule(id):
    rule = Rule.query.get(id)
    tags = Tag.query.all()
    clusters = Cluster.query.all()
    return render_template("view_rule.html",rule=rule,
        tags=tags,clusters=clusters)

@main.route('/rules/<int:id>/settings', methods=['POST'])
@login_required
def update_rule_settings(id):
    rule = Rule.query.get(id)
    rule.label = request.form.get("label")
    rule.description = request.form.get("description")
    rule.remediation = request.form.get("remediation")
    rule.severity = request.form.get("severity")
    if request.form.get("enabled") == "on":
        rule.enabled = True
    else:
        rule.enabled = False
    clusters = request.form.getlist('clusters[]')
    rule.set_clusters_by_id(clusters)
    tags = request.form.getlist('tags[]')
    rule.set_tags_by_name(tags,create_if_not=True)
    db.session.commit()
    flash("Updated settings")
    return redirect(url_for("main.view_rule",id=rule.id))

@main.route('/rules/<int:id>/delete', methods=['GET'])
@login_required
def delete_rule(id):
    rule = Rule.query.get(id)
    db.session.delete(rule)
    db.session.commit()
    flash("Deleted rule")
    return redirect(url_for("main.rules"))

@main.route('/rules/add', methods=['GET','POST'])
@login_required
def add_rule():
    new_rule = Rule.add()
    flash("Added Rule")
    return redirect(url_for("main.view_rule",id=new_rule.id))

@main.route('/events', methods=['GET'])
@login_required
def events():
    name = request.args.get('name', None, type=str)
    namespace = request.args.get('namespace', None, type=str)
    uid = request.args.get('uid', None, type=str)
    limit = request.args.get('limit', 50, type=int)
    update = request.args.get('update', 1, type=int)
    date_added = request.args.get('date_added', None, type=str)
    if not date_added:
        date_added = datetime.now() - timedelta(hours = 24)
    date_sort = request.args.get('date_sort', "gt", type=str)
    operations = request.args.getlist('operations')
    tags = request.args.getlist('tags')
    filters = {"name":name,"namespace":namespace,"tags":tags,
        "operations":operations,"date_added":date_added,"date_sort":date_sort,
        "limit":limit,"update":update,"uid":uid
    }
    operation_list = Event.get_operations_in_list()
    tags = Tag.query.filter(Tag.name != None).all()
    query_string = request.query_string.decode("utf-8")
    return render_template("events.html",filters=filters,
        operation_list=operation_list,tags=tags,query_string=query_string)

@main.route('/clusters/token', methods=['GET'])
@login_required
def generate_token_for_cluster():
    return render_template("generate_token.html")
