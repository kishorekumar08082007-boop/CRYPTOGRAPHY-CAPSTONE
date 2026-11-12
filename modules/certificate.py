import os
import json
import base64
import uuid
import logging
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from database import execute_query
from config import Config

logger = logging.getLogger(__name__)


def _get_fernet() -> Fernet:
    """Return a Fernet instance for encrypting/decrypting private keys."""
    key = Config.PRIVATE_KEY_ENCRYPTION_KEY
    if not key:
        raise ValueError("PRIVATE_KEY_ENCRYPTION_KEY is not set in environment.")
    return Fernet(key.encode() if isinstance(key, str) else key)


def generate_user_certificate(user_id: int, name: str, email: str) -> dict:
    """
    Generate RSA-2048 key pair and a self-signed digital certificate for a user.
    Stores encrypted private key on disk, public key and cert data in DB.
    """
    try:
        # Generate RSA-2048 private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Serialize keys to PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Encrypt private key at rest
        fernet = _get_fernet()
        encrypted_private_key = fernet.encrypt(private_pem)

        # Save encrypted private key to disk
        os.makedirs(Config.KEYS_FOLDER, exist_ok=True)
        key_filename = f"user_{user_id}_private.key.enc"
        key_path = os.path.join(Config.KEYS_FOLDER, key_filename)
        with open(key_path, 'wb') as f:
            f.write(encrypted_private_key)

        # Build certificate data (self-signed certificate metadata)
        serial_number = uuid.uuid4().hex.upper()
        issue_date = datetime.now(timezone.utc)
        expiry_date = issue_date + timedelta(days=365)

        cert_data = {
            'version': 'DSS-Self-Signed-v1',
            'serial_number': serial_number,
            'subject': {
                'common_name': name,
                'email': email,
                'organization': 'Digital Signature System (Local Demo)',
                'country': 'IN'
            },
            'issuer': {
                'common_name': 'DSS Local Demo CA [Self-Signed - NOT a trusted CA]',
                'organization': 'Digital Signature System Demo',
                'country': 'IN'
            },
            'issue_date': issue_date.isoformat(),
            'expiry_date': expiry_date.isoformat(),
            'key_algorithm': 'RSA-2048',
            'signature_algorithm': 'RSA-PSS with SHA-256',
            'notice': 'This is a self-signed certificate for academic/demonstration purposes only. It is NOT issued by a trusted Certificate Authority.'
        }
        cert_data_json = json.dumps(cert_data, indent=2)

        # Store in database
        cert_id = execute_query(
            """
            INSERT INTO certificates 
                (user_id, certificate_serial, public_key, certificate_data, issue_date, expiry_date, status)
            VALUES (%s, %s, %s, %s, %s, %s, 'active')
            """,
            (
                user_id,
                serial_number,
                public_pem,
                cert_data_json,
                issue_date.strftime('%Y-%m-%d %H:%M:%S'),
                expiry_date.strftime('%Y-%m-%d %H:%M:%S')
            ),
            lastrowid=True
        )

        logger.info(f"Certificate generated for user {user_id}, cert_id={cert_id}")
        return {'success': True, 'cert_id': cert_id, 'serial': serial_number}

    except Exception as e:
        logger.error(f"Certificate generation failed: {e}")
        return {'success': False, 'message': str(e)}


def get_user_certificate(user_id: int) -> dict | None:
    """Retrieve the active certificate for a user."""
    return execute_query(
        """
        SELECT id, certificate_serial, public_key, certificate_data,
               issue_date, expiry_date, status
        FROM certificates
        WHERE user_id = %s AND status = 'active'
        ORDER BY created_at DESC LIMIT 1
        """,
        (user_id,),
        fetch_one=True
    )


def get_certificate_by_id(cert_id: int) -> dict | None:
    """Retrieve a certificate by its ID."""
    return execute_query(
        """
        SELECT c.*, u.name, u.email
        FROM certificates c
        JOIN users u ON c.user_id = u.id
        WHERE c.id = %s
        """,
        (cert_id,),
        fetch_one=True
    )


def get_private_key(user_id: int):
    """Decrypt and return the private key object for a user. NEVER expose to browser."""
    key_path = os.path.join(Config.KEYS_FOLDER, f"user_{user_id}_private.key.enc")
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Private key file not found for user {user_id}")
    
    fernet = _get_fernet()
    with open(key_path, 'rb') as f:
        encrypted_pem = f.read()
    
    private_pem = fernet.decrypt(encrypted_pem)
    return serialization.load_pem_private_key(private_pem, password=None)


def is_certificate_valid(cert: dict) -> bool:
    """Check if a certificate is active and not expired."""
    if not cert:
        return False
    if cert['status'] != 'active':
        return False
    now = datetime.now(timezone.utc)
    expiry = cert['expiry_date']
    if isinstance(expiry, str):
        expiry = datetime.fromisoformat(expiry)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return now < expiry


def revoke_certificate(cert_id: int) -> dict:
    """Revoke a certificate (admin operation)."""
    execute_query(
        "UPDATE certificates SET status = 'revoked' WHERE id = %s",
        (cert_id,)
    )
    return {'success': True, 'message': 'Certificate revoked.'}


def get_all_certificates() -> list:
    """Get all certificates with user info (for admin)."""
    return execute_query(
        """
        SELECT c.id, c.certificate_serial, c.issue_date, c.expiry_date, c.status,
               u.name, u.email
        FROM certificates c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
        """,
        fetch=True
    )
