from flask import render_template, redirect, url_for, abort, flash, request, \
    current_app, jsonify
from . import main
from app.models import *
from flask_login import login_required,current_user
from app.utils.decorators import roles_required,roles_accepted
from app.utils.misc import generate_uuid

@main.route('/', methods=['GET'])
@login_required
def home():
    return render_template("dashboard.html")

@main.route('/clusters', methods=['GET'])
@login_required
def clusters():
    return render_template("dashboard.html")

@main.route('/clusters/<int:id>/token', methods=['GET'])
@login_required
def generate_token_for_cluster(id):
    cluster = Cluster.query.get(id)
    if not cluster:
        flash("Cluster does not exist","warning")
        return redirect(url_for("main.home"))
    return render_template("generate_token.html",cluster=cluster)
