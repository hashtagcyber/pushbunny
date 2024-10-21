import unittest
from flask import current_app
from app import create_app
from config import Config
from flask_login import login_user
from app.models.user import User
import base64

class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    # Add any test-specific configurations here

class TestSSHKeys(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        
        # Create a test user and log them in
        with self.app.test_request_context():
            self.test_user = User('test@example.com')
            login_user(self.test_user)

    def tearDown(self):
        self.app_context.pop()

    def test_request_ssh_key_page(self):
        response = self.client.get('/ssh_keys/request_ssh_key')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Request SSH Key', response.data)

    def test_request_ssh_key_api(self):
        # First, we need to add a credential for the user
        with self.app.app_context():
            current_app.credentials.append({
                'email': 'test@example.com',
                'credential_data': base64.b64encode(b'dummy_credential_data').decode('ascii')
            })

        response = self.client.post('/ssh_keys/request_ssh_key', json={})
        self.assertEqual(response.status_code, 200)
        self.assertIn('publicKey', response.json)

    # Add more tests for SSH key functionality

if __name__ == '__main__':
    unittest.main()
