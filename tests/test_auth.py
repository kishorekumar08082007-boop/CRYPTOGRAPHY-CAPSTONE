"""
tests/test_auth.py — Authentication module unit tests
Run with: py -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock
from werkzeug.security import generate_password_hash, check_password_hash


# ── Test password hashing ────────────────────────────────────────
class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        password = "SecurePass@123"
        hashed = generate_password_hash(password, method='pbkdf2:sha256:600000')
        assert hashed != password

    def test_correct_password_verifies(self):
        password = "SecurePass@123"
        hashed = generate_password_hash(password, method='pbkdf2:sha256:600000')
        assert check_password_hash(hashed, password) is True

    def test_wrong_password_fails(self):
        password = "SecurePass@123"
        hashed = generate_password_hash(password, method='pbkdf2:sha256:600000')
        assert check_password_hash(hashed, "WrongPassword") is False

    def test_different_hashes_for_same_password(self):
        """PBKDF2 uses a salt so each hash should be unique."""
        password = "SecurePass@123"
        h1 = generate_password_hash(password, method='pbkdf2:sha256:600000')
        h2 = generate_password_hash(password, method='pbkdf2:sha256:600000')
        assert h1 != h2


# ── Test register_user (mocked DB) ──────────────────────────────
class TestRegisterUser:
    @patch('modules.authentication.execute_query')
    @patch('modules.authentication.generate_user_certificate')
    def test_register_new_user_success(self, mock_cert, mock_query):
        mock_query.side_effect = [None, 1]  # no existing user, then lastrowid=1
        mock_cert.return_value = {'success': True, 'cert_id': 1}

        from modules.authentication import register_user
        result = register_user("Alice", "alice@test.com", "Password@123")

        assert result['success'] is True
        assert 'Registration successful' in result['message']

    @patch('modules.authentication.execute_query')
    def test_register_duplicate_email_fails(self, mock_query):
        mock_query.return_value = {'id': 1}  # existing user found

        from modules.authentication import register_user
        result = register_user("Alice", "alice@test.com", "Password@123")

        assert result['success'] is False
        assert 'already registered' in result['message']


# ── Test login_user (mocked DB) ─────────────────────────────────
class TestLoginUser:
    @patch('modules.authentication.execute_query')
    def test_login_valid_credentials(self, mock_query):
        pw = generate_password_hash("Password@123", method='pbkdf2:sha256:600000')
        mock_query.return_value = {
            'id': 1, 'name': 'Alice', 'email': 'alice@test.com',
            'password_hash': pw, 'role': 'user', 'is_active': 1
        }

        from modules.authentication import login_user
        result = login_user("alice@test.com", "Password@123")

        assert result['success'] is True
        assert result['user']['email'] == 'alice@test.com'

    @patch('modules.authentication.execute_query')
    def test_login_wrong_password(self, mock_query):
        pw = generate_password_hash("Password@123", method='pbkdf2:sha256:600000')
        mock_query.return_value = {
            'id': 1, 'name': 'Alice', 'email': 'alice@test.com',
            'password_hash': pw, 'role': 'user', 'is_active': 1
        }

        from modules.authentication import login_user
        result = login_user("alice@test.com", "WrongPassword")

        assert result['success'] is False
        assert 'Invalid' in result['message']

    @patch('modules.authentication.execute_query')
    def test_login_nonexistent_user(self, mock_query):
        mock_query.return_value = None

        from modules.authentication import login_user
        result = login_user("nobody@test.com", "Password@123")

        assert result['success'] is False

    @patch('modules.authentication.execute_query')
    def test_login_deactivated_user(self, mock_query):
        pw = generate_password_hash("Password@123", method='pbkdf2:sha256:600000')
        mock_query.return_value = {
            'id': 1, 'name': 'Alice', 'email': 'alice@test.com',
            'password_hash': pw, 'role': 'user', 'is_active': 0
        }

        from modules.authentication import login_user
        result = login_user("alice@test.com", "Password@123")

        assert result['success'] is False
        assert 'deactivated' in result['message']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
