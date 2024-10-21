from flask import Blueprint, render_template, request, jsonify, redirect, url_for, current_app, session
from flask_login import login_user, login_required, logout_user, current_user
from google.oauth2 import id_token
from google.auth.transport import requests
from app.models.user import User
from app.utils.helpers import json_response
from app.exceptions import InvalidCredentialsException, UnauthorizedException
from fido2.webauthn import (
    PublicKeyCredentialUserEntity,
    AuthenticatorAttachment,
    UserVerificationRequirement,
    RegistrationResponse,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    AuthenticatorData,
    CollectedClientData
)
from fido2.utils import websafe_decode
from datetime import datetime
import base64

bp = Blueprint('auth', __name__)

@bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard'))
    return render_template('index.html')

@bp.route('/login')
def login():
    return render_template('login.html')

@bp.route('/google_login', methods=['POST'])
def google_login():
    try:
        token = request.json['credential']
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), current_app.config['GOOGLE_CLIENT_ID'])
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise InvalidCredentialsException('Wrong issuer.')
        email = idinfo['email'].lower()
        if current_app.config['ALLOWED_DOMAINS'] and not any(email.endswith(domain) for domain in current_app.config['ALLOWED_DOMAINS']):
            raise UnauthorizedException('Domain not allowed')
        user = User(email)
        login_user(user)
        current_app.logger.info(f"User {email} logged in successfully")
        return jsonify({'success': True})
    except InvalidCredentialsException as e:
        current_app.logger.warning(f"Invalid credentials: {str(e)}")
        return jsonify({'error': str(e)}), 401
    except UnauthorizedException as e:
        current_app.logger.warning(f"Unauthorized access: {str(e)}")
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        current_app.logger.error(f"Error in google_login: {str(e)}")
        return jsonify({'error': 'Invalid token'}), 400

@bp.route('/logout')
@login_required
def logout():
    current_app.logger.info(f"User {current_user.id} logged out")
    logout_user()
    return redirect(url_for('auth.index'))

@bp.route("/register/begin", methods=["POST"])
@login_required
def register_begin():
    try:
        current_app.logger.debug(f"Raw request data: {request.data}")
        
        if not request.data:
            current_app.logger.warning("Received empty request body")
            return json_response({"error": "Empty request body"}, 400)

        json_data = request.get_json(silent=True)
        current_app.logger.debug(f"Parsed JSON data: {json_data}")

        email = current_user.id

        # Get existing credentials for this user
        existing_credentials = [cred['credential_data'] for cred in current_app.credentials if cred['email'] == email]
        
        user = PublicKeyCredentialUserEntity(
            id=email.encode(),
            name=email,
            display_name=email,
        )
        options, state = current_app.fido_server.register_begin(
            user,
            credentials=existing_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key_requirement=None,
        )
        current_app.logger.debug(f"Register begin options: {options}")
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
        current_app.logger.error(f"Error in register_begin: {str(e)}", exc_info=True)
        return json_response({"error": str(e)}, 500)

# Add the register_complete route here
@bp.route("/register/complete", methods=["POST"])
@login_required
def register_complete():
    try:
        current_app.logger.debug(f"Received register complete request: {request.json}")
        data = request.json
        
        if not data:
            return json_response({"error": "No data received"}, 400)
        
        try:
            reg_response = RegistrationResponse.from_dict(data)
        except Exception as e:
            current_app.logger.error(f"Error creating RegistrationResponse: {str(e)}")
            return json_response({"error": f"Invalid registration data: {str(e)}"}, 400)
        
        try:
            auth_data = current_app.fido_server.register_complete(
                session.pop('state'),
                reg_response
            )
        except Exception as e:
            current_app.logger.error(f"Error in server.register_complete: {str(e)}")
            return json_response({"error": f"Registration failed: {str(e)}"}, 400)
        
        credential_info = {
            "credential_data": auth_data.credential_data,
            "email": current_user.id,
            "registered_on": datetime.now().isoformat(),
            "key_type": "Security Key",
            "friendly_name": f"Security Key {len([c for c in current_app.credentials if c['email'] == current_user.id]) + 1}"
        }
        
        current_app.credentials.append(credential_info)
        
        current_app.logger.info(f"Registered new credential for email {current_user.id}: {credential_info['friendly_name']}")
        current_app.logger.debug(f"Current credentials: {current_app.credentials}")
        return json_response({"status": "OK"})
    except Exception as e:
        current_app.logger.error(f"Error in register_complete: {str(e)}", exc_info=True)
        return json_response({"error": str(e)}, 500)

@bp.route("/authenticate/begin", methods=["POST"])
@login_required
def authenticate_begin():
    try:
        user = current_user
        user_credentials = [
            cred for cred in current_app.credentials if cred['email'] == user.id
        ]
        
        if not user_credentials:
            return json_response({"error": "No credentials found for this user"}, 400)

        # Convert credentials to the correct format
        credentials = [
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=cred['credential_data'].credential_id
            )
            for cred in user_credentials
        ]

        auth_data, state = current_app.fido_server.authenticate_begin(credentials)
        
        session['state'] = state
        
        # Convert bytes to base64
        auth_data_json = {
            "publicKey": {
                "challenge": base64.b64encode(auth_data.public_key.challenge).decode('ascii'),
                "timeout": auth_data.public_key.timeout,
                "rpId": auth_data.public_key.rp_id,
                "allowCredentials": [{
                    "type": "public-key",
                    "id": base64.b64encode(cred.id).decode('ascii'),
                } for cred in auth_data.public_key.allow_credentials],
                "userVerification": auth_data.public_key.user_verification
            }
        }
        
        return json_response(auth_data_json)
    except Exception as e:
        current_app.logger.error(f"Error in authenticate_begin: {str(e)}", exc_info=True)
        return json_response({"error": str(e)}, 500)

@bp.route("/authenticate/complete", methods=["POST"])
@login_required
def authenticate_complete():
    try:
        current_app.logger.debug(f"Received authenticate complete request: {request.json}")
        user_credentials = [cred for cred in current_app.credentials if cred['email'] == current_user.id]
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
            authenticated_credential = current_app.fido_server.authenticate_complete(
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
            current_app.logger.error(f"Error in server.authenticate_complete: {str(e)}")
            return json_response({"error": str(e)}, 400)

        current_app.logger.info(f"Authentication successful using key: {key_name}")
        return json_response({"status": "OK", "key_name": key_name})
    except Exception as e:
        current_app.logger.error(f"Error in authenticate_complete: {str(e)}")
        return json_response({"error": str(e)}, 400)
