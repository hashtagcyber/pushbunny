import fido2.features
fido2.features.webauthn_json_mapping.enabled = True

import logging
from flask import Flask, send_from_directory, jsonify, render_template, request
from flask_cors import CORS
from flask_login import LoginManager
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.server import Fido2Server
from .models.user import User
from config import Config
from .exceptions import PushbunnyAuthException

login_manager = LoginManager()
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def create_app(config_class=Config):
    app = Flask(__name__, static_url_path='/static', template_folder='templates')
    app.config.from_object(config_class)

    # Set up logging
    logging.basicConfig(level=app.config['LOG_LEVEL'])
    app.logger.setLevel(app.config['LOG_LEVEL'])
    file_handler = logging.FileHandler('pushbunny.log')
    file_handler.setLevel(app.config['LOG_LEVEL'])
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    app.logger.addHandler(file_handler)

    # Update CORS configuration
    CORS(app, supports_credentials=True, resources={r"/*": {
        "origins": [f"http://{app.config['HOST']}:{app.config['PORT']}", "http://localhost:5001"],
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST", "OPTIONS"]
    }})

    login_manager.init_app(app)

    rp = PublicKeyCredentialRpEntity(name="Pushbunny Auth", id=app.config['HOST'])
    app.fido_server = Fido2Server(rp)

    app.credentials = []  # Initialize the credentials list

    from .routes import auth, ssh_keys, dashboard
    app.register_blueprint(auth.bp, url_prefix='/auth')
    app.register_blueprint(ssh_keys.bp, url_prefix='/ssh_keys')
    app.register_blueprint(dashboard.bp, url_prefix='/dashboard')

    @app.route('/static/<path:filename>')
    def serve_static(filename):
        return send_from_directory(app.static_folder, filename)

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
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
        return response

    @app.errorhandler(PushbunnyAuthException)
    def handle_exception(e):
        app.logger.error(f"PushbunnyAuthException: {str(e)}")
        return jsonify({"error": e.message}), e.status_code

    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

    @app.errorhandler(404)
    def page_not_found(e):
        app.logger.error(f"404 error: {request.url}")
        return render_template('404.html'), 404

    app.logger.info("Application started")
    return app
