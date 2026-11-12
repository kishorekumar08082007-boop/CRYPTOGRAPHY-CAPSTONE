"""
tests/test_verification.py — Verification logic tests
Run with: py -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from unittest.mock import patch


# ── Helpers ──────────────────────────────────────────────────────
def _make_keypair():
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return pk, pk.public_key()


def _sign(private_key, data: bytes) -> str:
    sig = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode('utf-8')


def _pub_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')


# ── Certificate validity checks ──────────────────────────────────
class TestCertificateValidity:
    def test_valid_cert(self):
        from modules.certificate import is_certificate_valid
        cert = {
            'status': 'active',
            'expiry_date': datetime.now(timezone.utc) + timedelta(days=100)
        }
        assert is_certificate_valid(cert) is True

    def test_expired_cert(self):
        from modules.certificate import is_certificate_valid
        cert = {
            'status': 'active',
            'expiry_date': datetime.now(timezone.utc) - timedelta(days=1)
        }
        assert is_certificate_valid(cert) is False

    def test_revoked_cert(self):
        from modules.certificate import is_certificate_valid
        cert = {
            'status': 'revoked',
            'expiry_date': datetime.now(timezone.utc) + timedelta(days=100)
        }
        assert is_certificate_valid(cert) is False

    def test_none_cert(self):
        from modules.certificate import is_certificate_valid
        assert is_certificate_valid(None) is False


# ── Verification logic ───────────────────────────────────────────
class TestVerificationLogic:
    @patch('modules.verification.execute_query')
    @patch('modules.verification.get_document_by_id')
    def test_valid_document_returns_valid(self, mock_get_doc, mock_query):
        """Original document with correct signature should return 'valid'."""
        private_key, public_key = _make_keypair()
        document = b"This is the original PDF content."
        sha256 = hashlib.sha256(document).hexdigest()
        signature_b64 = _sign(private_key, document)
        pub_pem = _pub_pem(public_key)

        future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        mock_get_doc.return_value = {
            'id': 1,
            'document_name': 'test.pdf',
            'sha256_hash': sha256,
            'digital_signature': signature_b64,
            'public_key': pub_pem,
            'certificate_serial': 'TESTSERIAL123',
            'cert_status': 'active',
            'cert_expiry': future,
            'owner_name': 'Test User',
            'owner_email': 'test@test.com',
            'signed_at': '2026-01-01 00:00:00'
        }
        mock_query.return_value = None  # for the INSERT log call

        from modules.verification import verify_document
        result = verify_document(1, document, 42)

        assert result['status'] == 'valid'
        assert result['color'] == 'green'
        assert result['details']['hashes_match'] is True
        assert result['details']['signature_valid'] is True

    @patch('modules.verification.execute_query')
    @patch('modules.verification.get_document_by_id')
    def test_tampered_document_returns_tampered(self, mock_get_doc, mock_query):
        """Document modified after signing should return 'tampered'."""
        private_key, public_key = _make_keypair()
        original = b"Original document content."
        tampered = b"Tampered document content!!!"
        sha256_original = hashlib.sha256(original).hexdigest()
        signature_b64 = _sign(private_key, original)
        pub_pem = _pub_pem(public_key)

        future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        mock_get_doc.return_value = {
            'id': 1,
            'document_name': 'test.pdf',
            'sha256_hash': sha256_original,
            'digital_signature': signature_b64,
            'public_key': pub_pem,
            'certificate_serial': 'TESTSERIAL123',
            'cert_status': 'active',
            'cert_expiry': future,
            'owner_name': 'Test User',
            'owner_email': 'test@test.com',
            'signed_at': '2026-01-01 00:00:00'
        }
        mock_query.return_value = None

        from modules.verification import verify_document
        result = verify_document(1, tampered, 42)

        assert result['status'] == 'tampered'
        assert result['color'] == 'orange'
        assert result['details']['hashes_match'] is False

    @patch('modules.verification.execute_query')
    @patch('modules.verification.get_document_by_id')
    def test_wrong_key_returns_invalid(self, mock_get_doc, mock_query):
        """Document signed with one key, verified with another → invalid."""
        private_key1, _ = _make_keypair()
        _, public_key2 = _make_keypair()  # Different key pair!

        document = b"Test document."
        sha256 = hashlib.sha256(document).hexdigest()
        signature_b64 = _sign(private_key1, document)
        wrong_pub_pem = _pub_pem(public_key2)

        future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        mock_get_doc.return_value = {
            'id': 1,
            'document_name': 'test.pdf',
            'sha256_hash': sha256,
            'digital_signature': signature_b64,
            'public_key': wrong_pub_pem,
            'certificate_serial': 'TESTSERIAL123',
            'cert_status': 'active',
            'cert_expiry': future,
            'owner_name': 'Test User',
            'owner_email': 'test@test.com',
            'signed_at': '2026-01-01 00:00:00'
        }
        mock_query.return_value = None

        from modules.verification import verify_document
        result = verify_document(1, document, 42)

        assert result['status'] == 'invalid'
        assert result['color'] == 'red'

    @patch('modules.verification.execute_query')
    @patch('modules.verification.get_document_by_id')
    def test_missing_document_record_returns_invalid(self, mock_get_doc, mock_query):
        mock_get_doc.return_value = None
        mock_query.return_value = None

        from modules.verification import verify_document
        result = verify_document(999, b"anything", 42)

        assert result['status'] == 'invalid'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
