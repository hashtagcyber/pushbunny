from flask import Flask, session, request, jsonify, render_template, send_from_directory
from flask_cors import CORS, cross_origin
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
import fido2.features
import logging
import base64
import json
from enum import Enum

logging.basicConfig(level=logging.DEBUG)

fido2.features.webauthn_json_mapping.enabled = True

app = Flask(__name__, static_url_path="")
CORS(app, supports_credentials=True, resources={r"/*": {
    "origins": ["http://localhost:5001"],
    "allow_headers": ["Content-Type", "Authorization"],
    "methods": ["GET", "POST", "OPTIONS"]
}})

app.secret_key = os.urandom(32)

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
    return render_template('index.html')

@app.route("/register")
def register():
    return render_template('register.html'), 200, {'Content-Type': 'text/html'}

@app.route("/authenticate")
def authenticate():
    return render_template('authenticate.html'), 200, {'Content-Type': 'text/html'}

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route("/register/begin", methods=["POST"])
def register_begin():
    try:
        app.logger.debug(f"Received register begin request: {request.json}")
        email = request.json.get('email')
        if not email:
            return json_response({"error": "Email is required"}, 400)

        # Check if the email is already registered
        existing_credential = next((cred for cred, registered_email in credentials if registered_email == email), None)
        if existing_credential:
            return json_response({"error": "Email is already registered"}, 400)

        # Store email in session
        session['email'] = email

        user = PublicKeyCredentialUserEntity(
            id=email.encode(),  # Use email as the user handle
            name=email,
            display_name=email,
        )
        options, state = server.register_begin(
            user,
            credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
            authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
            resident_key_requirement=None,  # You can set this if needed
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
                    "id": base64.urlsafe_b64encode(cred.id).decode('ascii').rstrip('='),
                    "type": cred.type,
                    "transports": cred.transports if cred.transports else None
                } for cred in (options.public_key.exclude_credentials or [])],
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "userVerification": "preferred",
                    "requireResidentKey": False  # Set to True if you want to require resident keys
                },
                "attestation": options.public_key.attestation,
                "extensions": options.public_key.extensions
            }
        }
        
        # Remove None values from excludeCredentials
        for cred in options_json["publicKey"]["excludeCredentials"]:
            cred = {k: v for k, v in cred.items() if v is not None}
        
        return json_response(options_json)
    except Exception as e:
        app.logger.error(f"Error in register_begin: {str(e)}")
        return json_response({"error": str(e)}, 500)

@app.route("/register/complete", methods=["POST"])
def register_complete():
    try:
        app.logger.debug(f"Received register complete request: {request.json}")
        data = request.json
        
        # Create a RegistrationResponse object
        reg_response = RegistrationResponse.from_dict(data)
        
        # Complete the registration
        auth_data = server.register_complete(
            session['state'],
            reg_response
        )
        
        # Store the credential data along with the email
        credential_data = auth_data.credential_data
        email = session.get('email')  # Get the email from the session
        if not email:
            return json_response({"error": "Email not found in session"}, 400)
        
        credentials.append((credential_data, email))
        
        app.logger.info(f"Registered credential for email {email}: {credential_data}")
        app.logger.debug(f"Current credentials: {credentials}")
        return json_response({"status": "OK"})
    except Exception as e:
        app.logger.error(f"Error in register_complete: {str(e)}")
        return json_response({"error": str(e)}, 400)

@app.route("/authenticate/begin", methods=["POST"])
def authenticate_begin():
    try:
        app.logger.debug(f"Received authenticate begin request: {request.json}")
        if not credentials:
            return json_response({"error": "No registered credentials found"}, 400)
        
        # Convert AttestedCredentialData to PublicKeyCredentialDescriptor
        allowed_credentials = [
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=cred.credential_id
            ) for cred, _ in credentials  # Unpack the tuple here
        ]
        
        options, state = server.authenticate_begin(allowed_credentials)
        app.logger.debug(f"Authenticate begin options: {options}")
        session["state"] = state

        # Convert bytes to base64url and handle transports
        options_json = {
            "publicKey": {
                "challenge": base64.urlsafe_b64encode(options.public_key.challenge).decode('ascii').rstrip('='),
                "timeout": options.public_key.timeout,
                "rpId": options.public_key.rp_id,
                "allowCredentials": [{
                    "type": "public-key",
                    "id": base64.urlsafe_b64encode(cred.id).decode('ascii').rstrip('='),
                } for cred in options.public_key.allow_credentials],
                "userVerification": options.public_key.user_verification
            }
        }

        # Remove empty fields
        options_json["publicKey"] = {k: v for k, v in options_json["publicKey"].items() if v is not None}

        app.logger.debug(f"Sending options to client: {options_json}")
        return json_response(options_json)
    except Exception as e:
        app.logger.error(f"Error in authenticate_begin: {str(e)}")
        return json_response({"error": str(e)}, 500)

@app.route("/authenticate/complete", methods=["POST"])
def authenticate_complete():
    try:
        app.logger.debug(f"Received authenticate complete request: {request.json}")
        if not credentials:
            return json_response({"error": "No registered credentials found"}, 400)
        
        data = request.json
        if not data:
            return json_response({"error": "No data received"}, 400)

        try:
            credential_id = base64.urlsafe_b64decode(data['rawId'] + '==')
            client_data_json = base64.urlsafe_b64decode(data['response']['clientDataJSON'] + '==')
            auth_data_raw = base64.urlsafe_b64decode(data['response']['authenticatorData'] + '==')
            signature = base64.urlsafe_b64decode(data['response']['signature'] + '==')
            
            client_data = CollectedClientData(client_data_json)
            auth_data = AuthenticatorData(auth_data_raw)
            
        except KeyError as e:
            return json_response({"error": f"Missing required field: {str(e)}"}, 400)
        except Exception as e:
            return json_response({"error": f"Error decoding data: {str(e)}"}, 400)

        try:
            credential_data_list = [cred for cred, _ in credentials]
            server.authenticate_complete(
                session.pop('state'),
                credential_data_list,
                credential_id,
                client_data,
                auth_data,
                signature
            )
        except Exception as e:
            app.logger.error(f"Error in server.authenticate_complete: {str(e)}")
            return json_response({"error": str(e)}, 400)

        app.logger.info("Authentication successful")
        return json_response({"status": "OK"})
    except Exception as e:
        app.logger.error(f"Error in authenticate_complete: {str(e)}")
        return json_response({"error": str(e)}, 400)

@app.after_request
def add_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "connect-src 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == "__main__":
    app.run(host="localhost", port=5001, debug=True)
