from flask import Blueprint, render_template, current_app, request
from flask_login import login_required, current_user
from app.services.ssh_key_service import request_ssh_key, sign_ssh_key, verify_ssh_key
from app.utils.helpers import json_response

bp = Blueprint('ssh_keys', __name__)

@bp.route("/request_ssh_key", methods=["GET"])
@login_required
def request_ssh_key_form():
    current_app.logger.info(f"User {current_user.id} accessed SSH key request form")
    return render_template('request_ssh_key.html')

@bp.route("/request_ssh_key", methods=["POST"])
@login_required
def request_ssh_key_route():
    current_app.logger.info(f"User {current_user.id} requested new SSH key")
    return request_ssh_key()

@bp.route("/sign_ssh_key", methods=["POST"])
@login_required
def sign_ssh_key_route():
    current_app.logger.info(f"User {current_user.id} requested to sign SSH key")
    return sign_ssh_key()

@bp.route("/verify_ssh_key", methods=["POST"])
@login_required
def verify_ssh_key_route():
    current_app.logger.info(f"User {current_user.id} requested to verify SSH key")
    return verify_ssh_key()
