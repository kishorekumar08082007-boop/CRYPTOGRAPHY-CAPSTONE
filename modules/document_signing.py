import os
import hashlib
import base64
import uuid
import logging
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from database import execute_query
from config import Config
from modules.certificate import get_user_certificate, get_private_key, is_certificate_valid

logger = logging.getLogger(__name__)


def allowed_file(filename: str) -> bool:
    """Check if the file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def compute_sha256(file_bytes: bytes) -> str:
    """Compute the SHA-256 hash of the given bytes and return hex string."""
    return hashlib.sha256(file_bytes).hexdigest()


def sign_document(user_id: int, file_bytes: bytes, original_filename: str) -> dict:
    """
    Sign a document using the user's RSA-2048 private key with RSA-PSS and SHA-256.
    Saves the file and stores metadata in the database.
    Returns dict with 'success', 'document_id', 'sha256_hash', 'message'.
    """
    # Get user's active certificate
    cert = get_user_certificate(user_id)
    if not cert:
        return {'success': False, 'message': 'No active certificate found. Please generate a certificate first.'}
    if not is_certificate_valid(cert):
        return {'success': False, 'message': 'Your certificate is expired or revoked. Please contact the administrator.'}

    # Compute SHA-256 hash of document bytes
    sha256_hash = compute_sha256(file_bytes)

    # Get private key (server-side only)
    try:
        private_key = get_private_key(user_id)
    except FileNotFoundError:
        return {'success': False, 'message': 'Private key not found. Please regenerate your certificate.'}
    except Exception as e:
        logger.error(f"Private key retrieval failed for user {user_id}: {e}")
        return {'success': False, 'message': 'Failed to load private key.'}

    # Sign the document bytes using RSA-PSS with SHA-256
    try:
        signature_bytes = private_key.sign(
            file_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Encode signature as base64 for database storage
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
    except Exception as e:
        logger.error(f"Signing failed for user {user_id}: {e}")
        return {'success': False, 'message': 'Document signing failed.'}

    # Save file to uploads folder
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    safe_filename = f"{uuid.uuid4().hex}_{original_filename}"
    file_path = os.path.join(Config.UPLOAD_FOLDER, safe_filename)
    with open(file_path, 'wb') as f:
        f.write(file_bytes)

    # Store in database
    try:
        doc_id = execute_query(
            """
            INSERT INTO documents
                (user_id, document_name, stored_file_path, sha256_hash,
                 digital_signature, certificate_id, signed_at, file_size)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_id,
                original_filename,
                safe_filename,  # Store only filename, not full path
                sha256_hash,
                signature_b64,
                cert['id'],
                datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                len(file_bytes)
            ),
            lastrowid=True
        )
    except Exception as e:
        logger.error(f"Failed to store document record: {e}")
        # Clean up file
        if os.path.exists(file_path):
            os.remove(file_path)
        return {'success': False, 'message': 'Failed to save document record.'}

    logger.info(f"Document signed: doc_id={doc_id}, user_id={user_id}, hash={sha256_hash[:16]}...")
    return {
        'success': True,
        'document_id': doc_id,
        'sha256_hash': sha256_hash,
        'message': 'Document signed successfully.'
    }


def get_user_documents(user_id: int) -> list:
    """Get all documents belonging to a user."""
    return execute_query(
        """
        SELECT d.id, d.document_name, d.sha256_hash, d.signed_at, d.file_size,
               d.stored_file_path, c.certificate_serial, c.status as cert_status
        FROM documents d
        JOIN certificates c ON d.certificate_id = c.id
        WHERE d.user_id = %s
        ORDER BY d.signed_at DESC
        """,
        (user_id,),
        fetch=True
    )


def get_document_by_id(doc_id: int, user_id: int = None) -> dict | None:
    """
    Get a document by ID. If user_id is provided, verifies ownership.
    Returns None if not found or access denied.
    """
    query = """
        SELECT d.*, c.public_key, c.certificate_serial, c.status as cert_status,
               c.expiry_date as cert_expiry, u.name as owner_name, u.email as owner_email
        FROM documents d
        JOIN certificates c ON d.certificate_id = c.id
        JOIN users u ON d.user_id = u.id
        WHERE d.id = %s
    """
    params = [doc_id]
    if user_id is not None:
        query += " AND d.user_id = %s"
        params.append(user_id)
    
    return execute_query(query, tuple(params), fetch_one=True)


def get_all_documents_admin() -> list:
    """Get all documents (for admin)."""
    return execute_query(
        """
        SELECT d.id, d.document_name, d.sha256_hash, d.signed_at, d.file_size,
               u.name as owner_name, u.email as owner_email,
               c.certificate_serial
        FROM documents d
        JOIN users u ON d.user_id = u.id
        JOIN certificates c ON d.certificate_id = c.id
        ORDER BY d.signed_at DESC
        LIMIT 100
        """,
        fetch=True
    )
