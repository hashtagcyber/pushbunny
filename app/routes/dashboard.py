from flask import Blueprint, render_template, redirect, url_for, current_app, request, jsonify
from flask_login import login_required, current_user
from app.utils.helpers import json_response

bp = Blueprint('dashboard', __name__)

@bp.route('/')
@login_required
def dashboard():
    user_credentials = [cred for cred in current_app.credentials if cred['email'] == current_user.id]
    current_app.logger.info(f"User {current_user.id} accessed dashboard")
    return render_template('dashboard.html', credentials=user_credentials)

@bp.route('/remove_key/<credential_id>')
@login_required
def remove_key(credential_id):
    current_app.credentials = [cred for cred in current_app.credentials if cred['credential_data'].credential_id.hex() != credential_id or cred['email'] != current_user.id]
    current_app.logger.info(f"User {current_user.id} removed key {credential_id}")
    return redirect(url_for('dashboard.dashboard'))

@bp.route('/test_key')
@login_required
def test_key():
    current_app.logger.info(f"User {current_user.id} accessed test key page")
    return render_template('test_key.html')

@bp.route('/edit_key_name', methods=['POST'])
@login_required
def edit_key_name():
    data = request.json
    credential_id = data.get('credential_id')
    new_name = data.get('new_name')

    if not credential_id or not new_name:
        current_app.logger.warning(f"User {current_user.id} attempted to edit key name with missing data")
        return jsonify({'error': 'Missing credential_id or new_name'}), 400

    for cred in current_app.credentials:
        if cred['credential_data'].credential_id.hex() == credential_id and cred['email'] == current_user.id:
            cred['friendly_name'] = new_name
            current_app.logger.info(f"User {current_user.id} edited key name for {credential_id}")
            return jsonify({'status': 'OK'})

    current_app.logger.warning(f"User {current_user.id} attempted to edit non-existent key {credential_id}")
    return jsonify({'error': 'Credential not found'}), 404
