from flask import current_app, session, request
from flask_login import current_user
from app.utils.helpers import json_response
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from fido2.webauthn import PublicKeyCredentialDescriptor, PublicKeyCredentialType, CollectedClientData, AuthenticatorData
import base64
import subprocess
import tempfile
import os

def request_ssh_key():
    try:
        # Generate a new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize the public key to OpenSSH format
        ssh_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')

        # Store the private key temporarily
        session['temp_private_key'] = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # Initiate MFA authentication
        user_credentials = [cred['credential_data'] for cred in current_app.credentials if cred['email'] == current_user.id]
        if not user_credentials:
            return json_response({"error": "No registered credentials found for this user"}, 400)
        
        # Convert credential_data to PublicKeyCredentialDescriptor if it's a string
        user_credentials = [
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=base64.b64decode(cred) if isinstance(cred, str) else cred.credential_id
            )
            for cred in user_credentials
        ]
        
        options, state = current_app.fido_server.authenticate_begin(user_credentials)
        session["state"] = state
        session["ssh_key_request"] = True  # Flag to indicate this authentication is for SSH key signing

        options_json = {
            "publicKey": {
                "challenge": base64.urlsafe_b64encode(options.public_key.challenge).decode('ascii').rstrip('='),
                "timeout": options.public_key.timeout,
                "rpId": options.public_key.rp_id,
                "allowCredentials": [{
                    "type": "public-key",
                    "id": base64.urlsafe_b64encode(cred.id).decode('ascii').rstrip('='),
                } for cred in user_credentials],
                "userVerification": options.public_key.user_verification
            }
        }

        return json_response(options_json)
    except Exception as e:
        current_app.logger.error(f"Error in request_ssh_key: {str(e)}")
        return json_response({"error": str(e)}, 500)

def sign_ssh_key():
    try:
        if not session.get("ssh_key_request"):
            return json_response({"error": "Invalid request"}, 400)

        # Verify MFA authentication
        auth_data = request.json
        user_credentials = [cred['credential_data'] for cred in current_app.credentials if cred['email'] == current_user.id]
        
        try:
            credential_id = base64.urlsafe_b64decode(auth_data['rawId'] + '==')
            client_data = CollectedClientData(base64.urlsafe_b64decode(auth_data['response']['clientDataJSON'] + '=='))
            auth_data_obj = AuthenticatorData(base64.urlsafe_b64decode(auth_data['response']['authenticatorData'] + '=='))
            signature = base64.urlsafe_b64decode(auth_data['response']['signature'] + '==')
            
            current_app.fido_server.authenticate_complete(
                session.pop('state'),
                user_credentials,
                credential_id,
                client_data,
                auth_data_obj,
                signature
            )
        except Exception as e:
            current_app.logger.error(f"Error in MFA verification: {str(e)}")
            return json_response({"error": "MFA verification failed"}, 400)

        # MFA verified, now sign the SSH key
        private_key = session.pop('temp_private_key', None)
        if not private_key:
            return json_response({"error": "No pending SSH key request"}, 400)

        # Write the private key to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as temp_key_file:
            temp_key_file.write(private_key)
            temp_key_path = temp_key_file.name

        try:
            # Generate public key from private key
            public_key_path = f"{temp_key_path}.pub"
            subprocess.run([
                "ssh-keygen",
                "-y",
                "-f", temp_key_path
            ], stdout=open(public_key_path, 'w'), check=True)

            # Use ssh-keygen to generate a certificate
            ca_private_key_path = current_app.config['SSH_CA_PRIVATE_KEY_PATH']
            cert_path = f"{temp_key_path}-cert.pub"
            subprocess.run([
                "ssh-keygen", 
                "-s", ca_private_key_path,
                "-I", f"{current_user.id}@pushbunny",
                "-n", current_user.id,
                "-V", "+1d",
                public_key_path
            ], check=True)

            # Read the generated certificate
            with open(cert_path, 'r') as cert_file:
                ssh_certificate = cert_file.read()

            return json_response({
                "private_key": private_key,
                "certificate": ssh_certificate
            })
        except subprocess.CalledProcessError as e:
            current_app.logger.error(f"Error signing SSH key: {str(e)}")
            return json_response({"error": "Failed to sign SSH key"}, 500)
        finally:
            # Clean up temporary files
            for file in [temp_key_path, f"{temp_key_path}.pub", cert_path]:
                if os.path.exists(file):
                    os.remove(file)

    except Exception as e:
        current_app.logger.error(f"Error in sign_ssh_key: {str(e)}")
        return json_response({"error": str(e)}, 500)

def verify_ssh_key():
    try:
        certificate = request.json.get('certificate')
        if not certificate:
            return json_response({"error": "No certificate provided"}, 400)

        current_app.logger.debug(f"Received certificate for verification: {certificate[:100]}...")  # Log first 100 chars

        # Write the certificate to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pub') as temp_cert_file:
            temp_cert_file.write(certificate)
            temp_cert_path = temp_cert_file.name

        try:
            # View certificate details
            cert_details = subprocess.check_output(['ssh-keygen', '-L', '-f', temp_cert_path], stderr=subprocess.STDOUT)
            cert_details_str = cert_details.decode('utf-8')
            current_app.logger.debug(f"Certificate details: {cert_details_str}")

            # Check if the certificate is signed by our CA
            ca_public_key_path = current_app.config['SSH_CA_PUBLIC_KEY_PATH']
            with open(ca_public_key_path, 'r') as ca_pub_file:
                ca_public_key = ca_pub_file.read().strip()

            # Extract the CA's key fingerprint from the certificate details
            ca_key_line = next((line for line in cert_details_str.split('\n') if "Signing CA:" in line), None)
            if ca_key_line:
                cert_ca_fingerprint = ca_key_line.split("Signing CA:", 1)[1].strip().split(" ", 2)[1]
                current_app.logger.debug(f"CA fingerprint from cert: {cert_ca_fingerprint}")

                # Generate fingerprint for our CA public key
                our_ca_fingerprint = subprocess.check_output(['ssh-keygen', '-lf', ca_public_key_path], stderr=subprocess.STDOUT).decode('utf-8').split(" ", 2)[1]
                current_app.logger.debug(f"Our CA fingerprint: {our_ca_fingerprint}")

                if cert_ca_fingerprint == our_ca_fingerprint:
                    return json_response({
                        "status": "OK",
                        "message": "Certificate is valid and signed by our CA",
                        "details": cert_details_str
                    })
                else:
                    return json_response({
                        "status": "Error",
                        "message": "Certificate is not signed by our CA",
                        "details": cert_details_str
                    }, 400)
            else:
                return json_response({
                    "status": "Error",
                    "message": "Could not find CA information in certificate",
                    "details": cert_details_str
                }, 400)

        except subprocess.CalledProcessError as e:
            current_app.logger.error(f"Error during certificate verification: {e.output.decode('utf-8')}")
            return json_response({
                "status": "Error",
                "message": "Certificate verification failed",
                "error": e.output.decode('utf-8')
            }, 400)
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_cert_path):
                os.remove(temp_cert_path)

    except Exception as e:
        current_app.logger.error(f"Error in verify_ssh_key: {str(e)}", exc_info=True)
        return json_response({"error": str(e)}, 500)
