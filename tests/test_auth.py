import unittest
from flask import current_app
from app import create_app
from app.models.user import User
from config import Config

class TestConfig(Config):
    TESTING = True
    # Add any test-specific configurations here

class TestAuth(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()

    def tearDown(self):
        self.app_context.pop()

    def test_login_page(self):
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login with Google', response.data)

    def test_logout_redirect(self):
        response = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Welcome to Pushbunny Auth', response.data)

    def test_user_model(self):
        user = User('test@example.com')
        self.assertEqual(user.id, 'test@example.com')
        self.assertTrue(user.is_authenticated)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_anonymous)

if __name__ == '__main__':
    unittest.main()
