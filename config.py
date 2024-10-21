import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY') or os.urandom(32)
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    ALLOWED_DOMAINS = os.getenv('ALLOWED_DOMAINS', '').split(',')
    SSH_CA_PRIVATE_KEY_PATH = os.getenv('SSH_CA_PRIVATE_KEY_PATH')
    SSH_CA_PUBLIC_KEY_PATH = os.getenv('SSH_CA_PUBLIC_KEY_PATH')
    DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    HOST = os.getenv('HOST', 'localhost')
    PORT = int(os.getenv('PORT', 5001))
