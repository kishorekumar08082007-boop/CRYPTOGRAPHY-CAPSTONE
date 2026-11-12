from werkzeug.security import generate_password_hash, check_password_hash
from database import execute_query
from modules.certificate import generate_user_certificate
import logging

logger = logging.getLogger(__name__)


def register_user(name: str, email: str, password: str) -> dict:
    """
    Register a new user. Returns dict with 'success' bool and 'message' string.
    Also generates an RSA key pair and certificate for the user.
    """
    # Check if email already exists
    existing = execute_query(
        "SELECT id FROM users WHERE email = %s",
        (email,),
        fetch_one=True
    )
    if existing:
        return {'success': False, 'message': 'Email address is already registered.'}

    # Hash the password
    password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')

    # Insert the user
    try:
        user_id = execute_query(
            "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 'user')",
            (name, email, password_hash),
            lastrowid=True
        )
    except Exception as e:
        logger.error(f"Failed to register user: {e}")
        return {'success': False, 'message': 'Registration failed. Please try again.'}

    # Generate RSA key pair and certificate
    try:
        cert_result = generate_user_certificate(user_id, name, email)
        if not cert_result['success']:
            logger.error(f"Certificate generation failed for user {user_id}: {cert_result['message']}")
            # Still return success for user creation, cert can be regenerated
    except Exception as e:
        logger.error(f"Certificate generation exception for user {user_id}: {e}")

    return {'success': True, 'message': 'Registration successful! Please log in.'}


def login_user(email: str, password: str) -> dict:
    """
    Authenticate a user. Returns dict with 'success', 'user' (dict), and 'message'.
    """
    user = execute_query(
        "SELECT id, name, email, password_hash, role, is_active FROM users WHERE email = %s",
        (email,),
        fetch_one=True
    )

    if not user:
        return {'success': False, 'message': 'Invalid email or password.'}

    if not user['is_active']:
        return {'success': False, 'message': 'Your account has been deactivated. Contact the administrator.'}

    if not check_password_hash(user['password_hash'], password):
        return {'success': False, 'message': 'Invalid email or password.'}

    return {
        'success': True,
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'role': user['role']
        },
        'message': f'Welcome back, {user["name"]}!'
    }


def get_user_by_id(user_id: int) -> dict | None:
    """Fetch a user by ID."""
    return execute_query(
        "SELECT id, name, email, role, is_active, created_at FROM users WHERE id = %s",
        (user_id,),
        fetch_one=True
    )


def get_all_users() -> list:
    """Fetch all users (for admin)."""
    return execute_query(
        "SELECT id, name, email, role, is_active, created_at FROM users ORDER BY created_at DESC",
        fetch=True
    )


def toggle_user_status(user_id: int) -> dict:
    """Activate or deactivate a user account (admin only)."""
    user = execute_query(
        "SELECT id, is_active FROM users WHERE id = %s",
        (user_id,),
        fetch_one=True
    )
    if not user:
        return {'success': False, 'message': 'User not found.'}
    new_status = 0 if user['is_active'] else 1
    execute_query(
        "UPDATE users SET is_active = %s WHERE id = %s",
        (new_status, user_id)
    )
    status_text = 'activated' if new_status else 'deactivated'
    return {'success': True, 'message': f'User account has been {status_text}.'}
