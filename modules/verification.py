import base64
import hashlib
import logging
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from database import execute_query
from modules.document_signing import get_document_by_id, compute_sha256
from modules.certificate import is_certificate_valid
import os
from config import Config

logger = logging.getLogger(__name__)


def verify_document(doc_id: int, uploaded_bytes: bytes, verifier_user_id: int) -> dict:
    """
    Verify a document's digital signature using RSA-PSS.
    
    Steps:
    1. Retrieve the stored document record (original hash + signature + public key).
    2. Recompute SHA-256 of the uploaded bytes.
    3. Compare hashes to detect tampering.
    4. Verify the RSA-PSS signature using the stored public key.
    5. Check certificate validity.
    6. Log the verification attempt.
    
    Returns dict with:
        status: 'valid' | 'invalid' | 'tampered'
        status_code: 'VALID' | 'INVALID' | 'TAMPERED'
        color: 'green' | 'red' | 'orange'
        message: human-readable result
        details: dict with technical details
    """
    # Retrieve stored document record
    doc = get_document_by_id(doc_id)
    if not doc:
        return _log_and_return(
            doc_id, verifier_user_id, 'invalid',
            'Document record not found in database.',
            {}, None
        )

    # Compute hash of uploaded file
    uploaded_hash = compute_sha256(uploaded_bytes)
    stored_hash = doc['sha256_hash']

    # Check certificate validity
    cert_valid = (
        doc['cert_status'] == 'active' and
        _check_cert_expiry(doc['cert_expiry'])
    )

    details = {
        'document_name': doc['document_name'],
        'owner_name': doc['owner_name'],
        'owner_email': doc['owner_email'],
        'certificate_serial': doc['certificate_serial'],
        'stored_hash': stored_hash,
        'computed_hash': uploaded_hash,
        'hashes_match': uploaded_hash == stored_hash,
        'certificate_status': doc['cert_status'],
        'certificate_valid': cert_valid,
        'signed_at': str(doc['signed_at'])
    }

    # Step 1: Check if hashes match (tamper detection)
    if uploaded_hash != stored_hash:
        details['verification_step'] = 'Hash comparison failed — document content has been modified after signing.'
        return _log_and_return(
            doc_id, verifier_user_id, 'tampered',
            'The document has been modified after signing. The SHA-256 hash does not match the original.',
            details, uploaded_hash
        )

    # Step 2: Verify the RSA-PSS signature
    try:
        public_key_pem = doc['public_key'].encode('utf-8')
        public_key = serialization.load_pem_public_key(public_key_pem)
        signature_bytes = base64.b64decode(doc['digital_signature'])

        public_key.verify(
            signature_bytes,
            uploaded_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Signature verified successfully
        details['verification_step'] = 'RSA-PSS signature verification passed.'
        details['signature_valid'] = True

    except InvalidSignature:
        details['verification_step'] = 'RSA-PSS signature verification failed — invalid signature.'
        details['signature_valid'] = False
        return _log_and_return(
            doc_id, verifier_user_id, 'invalid',
            'Digital signature verification failed. The signature is invalid or the document is corrupted.',
            details, uploaded_hash
        )
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        details['verification_step'] = f'Verification error: {str(e)}'
        details['signature_valid'] = False
        return _log_and_return(
            doc_id, verifier_user_id, 'invalid',
            f'Signature verification encountered an error: {str(e)}',
            details, uploaded_hash
        )

    # Step 3: Certificate validity (informational — still valid signature)
    if not cert_valid:
        details['verification_step'] = 'Signature valid but certificate is expired or revoked.'
        # Signature is still cryptographically valid, but cert is expired
        return _log_and_return(
            doc_id, verifier_user_id, 'valid',
            'Digital signature is cryptographically valid. Note: The signing certificate has expired or been revoked.',
            details, uploaded_hash
        )

    return _log_and_return(
        doc_id, verifier_user_id, 'valid',
        'Digital signature is VALID. The document is authentic and has not been modified.',
        details, uploaded_hash
    )


def _check_cert_expiry(expiry) -> bool:
    """Return True if certificate expiry is in the future."""
    if not expiry:
        return False
    now = datetime.now(timezone.utc)
    if isinstance(expiry, str):
        expiry = datetime.fromisoformat(expiry)
    if hasattr(expiry, 'tzinfo') and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return now < expiry


def _log_and_return(doc_id, verifier_id, status, message, details, uploaded_hash) -> dict:
    """Log the verification attempt and return the result dict."""
    import json
    color_map = {'valid': 'green', 'invalid': 'red', 'tampered': 'orange'}
    code_map = {'valid': 'VALID', 'invalid': 'INVALID', 'tampered': 'TAMPERED'}

    # Log to database
    try:
        execute_query(
            """
            INSERT INTO verification_logs
                (document_id, verified_by, verification_status, verification_date, details, uploaded_file_hash)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                doc_id,
                verifier_id,
                status,
                datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                json.dumps(details),
                uploaded_hash
            )
        )
    except Exception as e:
        logger.error(f"Failed to log verification attempt: {e}")

    return {
        'status': status,
        'status_code': code_map[status],
        'color': color_map[status],
        'message': message,
        'details': details
    }


def get_user_verification_history(user_id: int) -> list:
    """Get verification history for documents owned by the user, plus verifications done BY the user."""
    return execute_query(
        """
        SELECT vl.id, vl.verification_status, vl.verification_date, vl.details,
               vl.uploaded_file_hash,
               d.document_name, d.id as document_id,
               u.name as verifier_name
        FROM verification_logs vl
        LEFT JOIN documents d ON vl.document_id = d.id
        LEFT JOIN users u ON vl.verified_by = u.id
        WHERE vl.verified_by = %s OR d.user_id = %s
        ORDER BY vl.verification_date DESC
        LIMIT 50
        """,
        (user_id, user_id),
        fetch=True
    )


def get_all_verification_logs_admin() -> list:
    """Get all verification logs (for admin)."""
    return execute_query(
        """
        SELECT vl.id, vl.verification_status, vl.verification_date,
               d.document_name,
               u.name as verifier_name, u.email as verifier_email
        FROM verification_logs vl
        LEFT JOIN documents d ON vl.document_id = d.id
        LEFT JOIN users u ON vl.verified_by = u.id
        ORDER BY vl.verification_date DESC
        LIMIT 100
        """,
        fetch=True
    )
