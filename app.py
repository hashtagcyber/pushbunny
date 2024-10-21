from flask import Flask, session, request, jsonify, render_template, send_from_directory, redirect, url_for
from flask_cors import CORS, cross_origin
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from google.oauth2 import id_token
from google.auth.transport import requests
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    CollectedClientData,
    AuthenticatorData,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAttachment,
    UserVerificationRequirement
)
from fido2.server import Fido2Server
import os
from dotenv import load_dotenv
import fido2.features
import logging
import base64
import json
from enum import Enum
from datetime import datetime

load_dotenv()

logging.basicConfig(level=logging.DEBUG)

fido2.features.webauthn_json_mapping.enabled = True

app = Flask(__name__, static_url_path="")
CORS(app, supports_credentials=True, resources={r"/*": {
    "origins": ["http://localhost:5001"],
    "allow_headers": ["Content-Type", "Authorization"],
    "methods": ["GET", "POST", "OPTIONS"]
}})

app.secret_key = os.urandom(32)

app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['ALLOWED_DOMAINS'] = os.getenv('ALLOWED_DOMAINS', '').split(',')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, email):
        self.id = email

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

rp = PublicKeyCredentialRpEntity(name="Pushbunny Auth", id="localhost")
server = Fido2Server(rp)

credentials = []

def json_response(data, status=200):
    response = jsonify(data)
    response.status_code = status
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route("/register")
@login_required
def register():
    return render_template('register.html'), 200, {'Content-Type': 'text/html'}

@app.route("/authenticate")
@login_required
def authenticate():
    return render_template('authenticate.html'), 200, {'Content-Type': 'text/html'}

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route("/register/begin", methods=["POST"])
@login_required
def register_begin():
    try:
        app.logger.debug(f"Raw request data: {request.data}")
        
        if not request.data:
            app.logger.warning("Received empty request body")
            return json_response({"error": "Empty request body"}, 400)

        json_data = request.get_json(silent=True)
        app.logger.debug(f"Parsed JSON data: {json_data}")

        email = current_user.id

        # Get existing credentials for this user
        existing_credentials = [cred['credential_data'] for cred in credentials if cred['email'] == email]
        
        user = PublicKeyCredentialUserEntity(
            id=email.encode(),
            name=email,
            display_name=email,
        )
        options, state = server.register_begin(
            user,
            credentials=existing_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key_requirement=None,
        )
        app.logger.debug(f"Register begin options: {options}")
        session["state"] = state
        
        # Convert bytes to base64
        options_json = {
            "publicKey": {
                "rp": options.public_key.rp,
                "user": {
                    "id": base64.urlsafe_b64encode(options.public_key.user.id).decode('ascii').rstrip('='),
                    "name": options.public_key.user.name,
                    "displayName": options.public_key.user.display_name
                },
                "challenge": base64.urlsafe_b64encode(options.public_key.challenge).decode('ascii').rstrip('='),
                "pubKeyCredParams": options.public_key.pub_key_cred_params,
                "timeout": options.public_key.timeout,
                "excludeCredentials": [{
                    "id": base64.urlsafe_b64encode(cred.credential_id).decode('ascii').rstrip('='),
                    "type": "public-key",
                    "transports": ["usb", "nfc", "ble", "internal"],
                } for cred in existing_credentials],
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "userVerification": "preferred",
                    "requireResidentKey": False
                },
                "attestation": options.public_key.attestation,
                "extensions": options.public_key.extensions
            }
        }
        
        return json_response(options_json)
    except Exception as e:
        app.logger.error(f"Error in register_begin: {str(e)}", exc_info=True)
        return json_response({"error": str(e)}, 500)

@app.route("/register/complete", methods=["POST"])
@login_required
def register_complete():
    try:
        app.logger.debug(f"Received register complete request: {request.json}")
        data = request.json
        
        if not data:
            return json_response({"error": "No data received"}, 400)
        
        try:
            reg_response = RegistrationResponse.from_dict(data)
        except Exception as e:
            app.logger.error(f"Error creating RegistrationResponse: {str(e)}")
            return json_response({"error": f"Invalid registration data: {str(e)}"}, 400)
        
        try:
            auth_data = server.register_complete(
                session.pop('state'),
                reg_response
            )
        except Exception as e:
            app.logger.error(f"Error in server.register_complete: {str(e)}")
            return json_response({"error": f"Registration failed: {str(e)}"}, 400)
        
        credential_info = {
            "credential_data": auth_data.credential_data,
            "email": current_user.id,
            "registered_on": datetime.now().isoformat(),
            "key_type": "Security Key",
            "friendly_name": f"Security Key {len([c for c in credentials if c['email'] == current_user.id]) + 1}"
        }
        
        credentials.append(credential_info)
        
        app.logger.info(f"Registered new credential for email {current_user.id}: {credential_info['friendly_name']}")
        app.logger.debug(f"Current credentials: {credentials}")
        return json_response({"status": "OK"})
    except Exception as e:
        app.logger.error(f"Error in register_complete: {str(e)}", exc_info=True)
        return json_response({"error": str(e)}, 500)

@app.route("/authenticate/begin", methods=["POST"])
@login_required
def authenticate_begin():
    try:
        app.logger.debug(f"Received authenticate begin request: {request.json}")
        user_credentials = [cred['credential_data'] for cred in credentials if cred['email'] == current_user.id]
        if not user_credentials:
            return json_response({"error": "No registered credentials found for this user"}, 400)
        
        options, state = server.authenticate_begin(user_credentials)
        app.logger.debug(f"Authenticate begin options: {options}")
        session["state"] = state

        options_json = {
            "publicKey": {
                "challenge": base64.urlsafe_b64encode(options.public_key.challenge).decode('ascii').rstrip('='),
                "timeout": options.public_key.timeout,
                "rpId": options.public_key.rp_id,
                "allowCredentials": [{
                    "type": "public-key",
                    "id": base64.urlsafe_b64encode(cred.credential_id).decode('ascii').rstrip('='),
                } for cred in user_credentials],
                "userVerification": options.public_key.user_verification
            }
        }

        options_json["publicKey"] = {k: v for k, v in options_json["publicKey"].items() if v is not None}

        app.logger.debug(f"Sending options to client: {options_json}")
        return json_response(options_json)
    except Exception as e:
        app.logger.error(f"Error in authenticate_begin: {str(e)}")
        return json_response({"error": str(e)}, 500)

@app.route("/authenticate/complete", methods=["POST"])
@login_required
def authenticate_complete():
    try:
        app.logger.debug(f"Received authenticate complete request: {request.json}")
        user_credentials = [cred for cred in credentials if cred['email'] == current_user.id]
        if not user_credentials:
            return json_response({"error": "No registered credentials found for this user"}, 400)
        
        data = request.json
        if not data:
            return json_response({"error": "No data received"}, 400)

        try:
            credential_id = base64.urlsafe_b64decode(data['rawId'] + '==')
            client_data = CollectedClientData(base64.urlsafe_b64decode(data['response']['clientDataJSON'] + '=='))
            auth_data = AuthenticatorData(base64.urlsafe_b64decode(data['response']['authenticatorData'] + '=='))
            signature = base64.urlsafe_b64decode(data['response']['signature'] + '==')
            
        except KeyError as e:
            return json_response({"error": f"Missing required field: {str(e)}"}, 400)
        except Exception as e:
            return json_response({"error": f"Error decoding data: {str(e)}"}, 400)

        try:
            authenticated_credential = server.authenticate_complete(
                session.pop('state'),
                [cred['credential_data'] for cred in user_credentials],
                credential_id,
                client_data,
                auth_data,
                signature
            )
            
            # Find the friendly name of the authenticated key
            authenticated_key = next((cred for cred in user_credentials if cred['credential_data'] == authenticated_credential), None)
            key_name = authenticated_key['friendly_name'] if authenticated_key else "Unknown"
            
        except Exception as e:
            app.logger.error(f"Error in server.authenticate_complete: {str(e)}")
            return json_response({"error": str(e)}, 400)

        app.logger.info(f"Authentication successful using key: {key_name}")
        return json_response({"status": "OK", "key_name": key_name})
    except Exception as e:
        app.logger.error(f"Error in authenticate_complete: {str(e)}")
        return json_response({"error": str(e)}, 400)

@app.after_request
def add_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://accounts.google.com https://apis.google.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://accounts.google.com; "
        "font-src https://fonts.gstatic.com; "
        "frame-src https://accounts.google.com; "
        "img-src 'self' https://www.gstatic.com https://*.googleusercontent.com; "
        "connect-src 'self' https://accounts.google.com;"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/google_login', methods=['POST'])
def google_login():
    try:
        # Get the ID token sent by the client
        token = request.json['credential']

        # Verify the token
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), app.config['GOOGLE_CLIENT_ID'])

        # Check if the token is issued by Google
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        # Get the user's email address from the decoded token
        email = idinfo['email'].lower()

        if app.config['ALLOWED_DOMAINS'] and not any(email.endswith(domain) for domain in app.config['ALLOWED_DOMAINS']):
            return jsonify({'error': 'Domain not allowed'}), 403

        user = User(email)
        login_user(user)
        return jsonify({'success': True})
    except ValueError:
        return jsonify({'error': 'Invalid token'}), 400

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_credentials = [cred for cred in credentials if cred['email'] == current_user.id]
    return render_template('dashboard.html', credentials=user_credentials)

@app.route('/remove_key/<credential_id>')
@login_required
def remove_key(credential_id):
    global credentials
    credentials = [cred for cred in credentials if cred['credential_data'].credential_id.hex() != credential_id or cred['email'] != current_user.id]
    return redirect(url_for('dashboard'))

@app.route('/test_key')
@login_required
def test_key():
    return render_template('test_key.html')

@app.route('/edit_key_name', methods=['POST'])
@login_required
def edit_key_name():
    data = request.json
    credential_id = data.get('credential_id')
    new_name = data.get('new_name')

    if not credential_id or not new_name:
        return jsonify({'error': 'Missing credential_id or new_name'}), 400

    for cred in credentials:
        if cred['credential_data'].credential_id.hex() == credential_id and cred['email'] == current_user.id:
            cred['friendly_name'] = new_name
            return jsonify({'status': 'OK'})

    return jsonify({'error': 'Credential not found'}), 404

if __name__ == "__main__":
    app.run(host="localhost", port=5001, debug=True)

print(f"Google Client ID: {app.config['GOOGLE_CLIENT_ID']}")
