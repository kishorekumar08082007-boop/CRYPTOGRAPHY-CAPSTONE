"""
tests/test_signing.py — Document signing unit tests
Run with: py -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


# ── SHA-256 hashing ─────────────────────────────────────────────
class TestSHA256Hashing:
    def test_known_hash(self):
        """SHA-256 of empty bytes is well-known."""
        from modules.document_signing import compute_sha256
        result = compute_sha256(b"")
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_deterministic(self):
        from modules.document_signing import compute_sha256
        data = b"Hello, Digital Signature World!"
        assert compute_sha256(data) == compute_sha256(data)

    def test_different_content_different_hash(self):
        from modules.document_signing import compute_sha256
        h1 = compute_sha256(b"Original content")
        h2 = compute_sha256(b"Modified content")
        assert h1 != h2

    def test_one_bit_change_changes_hash(self):
        from modules.document_signing import compute_sha256
        data1 = bytearray(b"Test document content.")
        data2 = bytearray(b"Test document content.")
        data2[0] ^= 0x01  # flip one bit
        assert compute_sha256(bytes(data1)) != compute_sha256(bytes(data2))


# ── File extension validation ────────────────────────────────────
class TestFileValidation:
    def test_pdf_allowed(self):
        from modules.document_signing import allowed_file
        assert allowed_file("report.pdf") is True
        assert allowed_file("REPORT.PDF") is True

    def test_non_pdf_rejected(self):
        from modules.document_signing import allowed_file
        assert allowed_file("malware.exe") is False
        assert allowed_file("script.py") is False
        assert allowed_file("image.png") is False
        assert allowed_file("document.docx") is False

    def test_no_extension_rejected(self):
        from modules.document_signing import allowed_file
        assert allowed_file("nodotfile") is False


# ── RSA key generation and signing ──────────────────────────────
class TestRSASigning:
    @pytest.fixture(scope="class")
    def rsa_keypair(self):
        """Generate a real RSA-2048 key pair for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        return private_key, private_key.public_key()

    def test_key_size(self, rsa_keypair):
        private_key, _ = rsa_keypair
        assert private_key.key_size == 2048

    def test_sign_and_verify_success(self, rsa_keypair):
        """RSA-PSS signing and verification should succeed for original document."""
        private_key, public_key = rsa_keypair
        document = b"This is a test PDF document content."

        signature = private_key.sign(
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Should not raise
        public_key.verify(
            signature,
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def test_tampered_document_fails_verification(self, rsa_keypair):
        """Verifying a tampered document should raise InvalidSignature."""
        from cryptography.exceptions import InvalidSignature
        private_key, public_key = rsa_keypair
        original = b"Original document content."
        tampered = b"Modified document content."

        signature = private_key.sign(
            original,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with pytest.raises(InvalidSignature):
            public_key.verify(
                signature,
                tampered,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

    def test_signature_base64_round_trip(self, rsa_keypair):
        """Signature can be base64-encoded and decoded without loss."""
        private_key, _ = rsa_keypair
        data = b"test"
        sig = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        encoded = base64.b64encode(sig).decode('utf-8')
        decoded = base64.b64decode(encoded)
        assert decoded == sig

    def test_wrong_public_key_fails(self, rsa_keypair):
        """Verifying with a different public key should fail."""
        from cryptography.exceptions import InvalidSignature
        private_key, _ = rsa_keypair
        other_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_public_key = other_private.public_key()

        document = b"Test document."
        signature = private_key.sign(
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with pytest.raises(InvalidSignature):
            wrong_public_key.verify(
                signature,
                document,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )


# ── Fernet private key encryption ───────────────────────────────
class TestPrivateKeyEncryption:
    def test_encrypt_decrypt_private_key(self):
        """Private key should survive encrypt → decrypt cycle unchanged."""
        from cryptography.fernet import Fernet

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted = f.encrypt(pem)
        decrypted_pem = f.decrypt(encrypted)

        assert pem == decrypted_pem

    def test_encrypted_key_is_not_plaintext(self):
        from cryptography.fernet import Fernet
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted = f.encrypt(pem)
        assert b"BEGIN PRIVATE KEY" not in encrypted


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
