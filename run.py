from app import create_app
from config import Config

app = create_app()

if __name__ == "__main__":
    if not app.config['SSH_CA_PRIVATE_KEY_PATH'] or not app.config['SSH_CA_PUBLIC_KEY_PATH']:
        app.logger.error("SSH_CA_PRIVATE_KEY_PATH or SSH_CA_PUBLIC_KEY_PATH is not set in the environment variables.")
        exit(1)
    app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'])

app.logger.info(f"Google Client ID: {app.config['GOOGLE_CLIENT_ID']}")
app.logger.info(f"SSH CA Private Key Path: {app.config['SSH_CA_PRIVATE_KEY_PATH']}")
app.logger.info(f"SSH CA Public Key Path: {app.config['SSH_CA_PUBLIC_KEY_PATH']}")
