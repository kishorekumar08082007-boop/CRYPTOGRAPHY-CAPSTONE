import os
import io
import json
import base64
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, jsonify, abort
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import qrcode
from PIL import Image

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Import config and modules
from config import Config
from database import execute_query, init_db_schema
from modules.authentication import (
    register_user, login_user, get_user_by_id,
    get_all_users, toggle_user_status
)
from modules.certificate import (
    get_user_certificate, get_certificate_by_id,
    generate_user_certificate, revoke_certificate,
    get_all_certificates, is_certificate_valid
)
from modules.document_signing import (
    sign_document, get_user_documents,
    get_document_by_id, allowed_file, get_all_documents_admin
)
from modules.verification import (
    verify_document, get_user_verification_history,
    get_all_verification_logs_admin
)

# ---------------------------------------------------------------------------
# App initialization
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

csrf = CSRFProtect(app)

# Ensure required folders exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(Config.CERTIFICATES_FOLDER, exist_ok=True)
os.makedirs(Config.KEYS_FOLDER, exist_ok=True)


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Template filters
# ---------------------------------------------------------------------------
@app.template_filter('format_datetime')
def format_datetime(value):
    if not value:
        return 'N/A'
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except Exception:
            return value
    return value.strftime('%d %b %Y, %H:%M UTC')


@app.template_filter('truncate_hash')
def truncate_hash(value, length=16):
    if not value:
        return ''
    return value[:length] + '...'


@app.template_filter('file_size_fmt')
def file_size_fmt(size_bytes):
    if not size_bytes:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        # Basic validation
        errors = []
        if not name or len(name) < 2:
            errors.append('Full name must be at least 2 characters.')
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html', name=name, email=email)

        result = register_user(name, email, password)
        if result['success']:
            flash(result['message'], 'success')
            return redirect(url_for('login'))
        else:
            flash(result['message'], 'danger')
            return render_template('register.html', name=name, email=email)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        result = login_user(email, password)
        if result['success']:
            user = result['user']
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            session['role'] = user['role']
            flash(result['message'], 'success')
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash(result['message'], 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# User Dashboard
# ---------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']

    # Get stats from DB
    total_docs = execute_query(
        "SELECT COUNT(*) as cnt FROM documents WHERE user_id = %s",
        (user_id,), fetch_one=True
    )['cnt']

    total_verif = execute_query(
        "SELECT COUNT(*) as cnt FROM verification_logs WHERE verified_by = %s",
        (user_id,), fetch_one=True
    )['cnt']

    valid_verif = execute_query(
        "SELECT COUNT(*) as cnt FROM verification_logs WHERE verified_by = %s AND verification_status = 'valid'",
        (user_id,), fetch_one=True
    )['cnt']

    failed_verif = execute_query(
        "SELECT COUNT(*) as cnt FROM verification_logs WHERE verified_by = %s AND verification_status != 'valid'",
        (user_id,), fetch_one=True
    )['cnt']

    cert = get_user_certificate(user_id)
    cert_valid = is_certificate_valid(cert) if cert else False

    recent_docs = execute_query(
        """
        SELECT d.id, d.document_name, d.signed_at, d.sha256_hash
        FROM documents d WHERE d.user_id = %s
        ORDER BY d.signed_at DESC LIMIT 5
        """,
        (user_id,), fetch=True
    )

    return render_template('dashboard.html',
        total_docs=total_docs,
        total_verif=total_verif,
        valid_verif=valid_verif,
        failed_verif=failed_verif,
        cert=cert,
        cert_valid=cert_valid,
        recent_docs=recent_docs
    )


# ---------------------------------------------------------------------------
# Certificate Management
# ---------------------------------------------------------------------------
@app.route('/certificates')
@login_required
def certificates():
    user_id = session['user_id']
    cert = get_user_certificate(user_id)
    cert_valid = is_certificate_valid(cert) if cert else False
    cert_data = None
    if cert and cert.get('certificate_data'):
        try:
            cert_data = json.loads(cert['certificate_data'])
        except Exception:
            cert_data = None
    return render_template('certificates.html', cert=cert, cert_valid=cert_valid, cert_data=cert_data)


@app.route('/certificates/regenerate', methods=['POST'])
@login_required
def regenerate_certificate():
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    result = generate_user_certificate(user_id, user['name'], user['email'])
    if result['success']:
        flash('New certificate and key pair generated successfully.', 'success')
    else:
        flash(f"Certificate generation failed: {result.get('message')}", 'danger')
    return redirect(url_for('certificates'))


@app.route('/certificates/download')
@login_required
def download_certificate():
    user_id = session['user_id']
    cert = get_user_certificate(user_id)
    if not cert:
        flash('No certificate found.', 'warning')
        return redirect(url_for('certificates'))
    cert_data = cert.get('certificate_data', '{}')
    cert_bytes = cert_data.encode('utf-8')
    return send_file(
        io.BytesIO(cert_bytes),
        mimetype='application/json',
        as_attachment=True,
        download_name=f"certificate_{cert['certificate_serial'][:8]}.json"
    )


# ---------------------------------------------------------------------------
# Document Signing
# ---------------------------------------------------------------------------
@app.route('/sign', methods=['GET', 'POST'])
@login_required
def sign_document_route():
    user_id = session['user_id']
    cert = get_user_certificate(user_id)
    cert_valid = is_certificate_valid(cert) if cert else False

    if request.method == 'POST':
        if not cert_valid:
            flash('You need a valid certificate to sign documents.', 'danger')
            return redirect(url_for('sign_document_route'))

        if 'document' not in request.files:
            flash('No file uploaded.', 'danger')
            return redirect(url_for('sign_document_route'))

        file = request.files['document']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('sign_document_route'))

        if not allowed_file(file.filename):
            flash('Only PDF files are allowed.', 'danger')
            return redirect(url_for('sign_document_route'))

        file_bytes = file.read()
        if len(file_bytes) > Config.MAX_CONTENT_LENGTH:
            flash('File too large. Maximum size is 16 MB.', 'danger')
            return redirect(url_for('sign_document_route'))
        if len(file_bytes) == 0:
            flash('The uploaded file is empty.', 'danger')
            return redirect(url_for('sign_document_route'))

        original_filename = secure_filename(file.filename)
        result = sign_document(user_id, file_bytes, original_filename)

        if result['success']:
            flash(f'Document signed successfully! SHA-256: {result["sha256_hash"][:32]}...', 'success')
            return redirect(url_for('sign_success', doc_id=result['document_id']))
        else:
            flash(result['message'], 'danger')

    documents = get_user_documents(user_id)
    return render_template('sign_document.html', cert=cert, cert_valid=cert_valid, documents=documents)


@app.route('/sign/success/<int:doc_id>')
@login_required
def sign_success(doc_id):
    user_id = session['user_id']
    doc = get_document_by_id(doc_id, user_id)
    if not doc:
        abort(404)
    
    # Generate QR code for document verification
    verify_url = f"http://localhost:5000/verify?doc_id={doc_id}"
    qr = qrcode.QRCode(version=1, box_size=6, border=4)
    qr.add_data(verify_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color='#1a3a5c', back_color='white')
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return render_template('sign_success.html', doc=doc, qr_b64=qr_b64, verify_url=verify_url)


@app.route('/documents/download/<int:doc_id>')
@login_required
def download_document(doc_id):
    user_id = session['user_id']
    doc = get_document_by_id(doc_id, user_id)
    if not doc:
        abort(404)
    file_path = os.path.join(Config.UPLOAD_FOLDER, doc['stored_file_path'])
    if not os.path.exists(file_path):
        flash('File not found on server.', 'danger')
        return redirect(url_for('sign_document_route'))
    return send_file(
        file_path,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=doc['document_name']
    )


# ---------------------------------------------------------------------------
# Document Verification
# ---------------------------------------------------------------------------
@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    user_id = session['user_id']
    documents = get_user_documents(user_id)
    prefill_doc_id = request.args.get('doc_id', type=int)

    if request.method == 'POST':
        doc_id = request.form.get('doc_id', type=int)
        if not doc_id:
            flash('Please select a document to verify.', 'danger')
            return redirect(url_for('verify'))

        if 'document' not in request.files or request.files['document'].filename == '':
            flash('Please upload the document file for verification.', 'danger')
            return redirect(url_for('verify'))

        file = request.files['document']
        uploaded_bytes = file.read()

        if len(uploaded_bytes) == 0:
            flash('The uploaded file is empty.', 'danger')
            return redirect(url_for('verify'))

        result = verify_document(doc_id, uploaded_bytes, user_id)

        return render_template('verify_result.html',
            result=result,
            doc_id=doc_id,
            documents=documents
        )

    return render_template('verify_document.html', documents=documents, prefill_doc_id=prefill_doc_id)


# ---------------------------------------------------------------------------
# Verification History
# ---------------------------------------------------------------------------
@app.route('/history')
@login_required
def history():
    user_id = session['user_id']
    logs = get_user_verification_history(user_id)
    return render_template('history.html', logs=logs)


# ---------------------------------------------------------------------------
# Admin Dashboard
# ---------------------------------------------------------------------------
@app.route('/admin')
@admin_required
def admin_dashboard():
    total_users = execute_query("SELECT COUNT(*) as cnt FROM users", fetch_one=True)['cnt']
    total_certs = execute_query("SELECT COUNT(*) as cnt FROM certificates", fetch_one=True)['cnt']
    total_docs = execute_query("SELECT COUNT(*) as cnt FROM documents", fetch_one=True)['cnt']
    total_verif = execute_query("SELECT COUNT(*) as cnt FROM verification_logs", fetch_one=True)['cnt']
    valid_verif = execute_query("SELECT COUNT(*) as cnt FROM verification_logs WHERE verification_status = 'valid'", fetch_one=True)['cnt']

    users = get_all_users()
    certs = get_all_certificates()
    recent_verif = get_all_verification_logs_admin()
    recent_docs = get_all_documents_admin()

    return render_template('admin.html',
        total_users=total_users,
        total_certs=total_certs,
        total_docs=total_docs,
        total_verif=total_verif,
        valid_verif=valid_verif,
        users=users,
        certs=certs,
        recent_verif=recent_verif[:10],
        recent_docs=recent_docs[:10]
    )


@app.route('/admin/toggle_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('admin_dashboard'))
    result = toggle_user_status(user_id)
    flash(result['message'], 'success' if result['success'] else 'danger')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/revoke_cert/<int:cert_id>', methods=['POST'])
@admin_required
def admin_revoke_cert(cert_id):
    result = revoke_certificate(cert_id)
    flash(result['message'], 'success' if result['success'] else 'danger')
    return redirect(url_for('admin_dashboard'))


# ---------------------------------------------------------------------------
# Setup / Initialization
# ---------------------------------------------------------------------------
def setup_admin():
    """Create the default admin account if it doesn't exist."""
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@localdemo.test')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin@123')
    admin_name = 'System Administrator'

    existing = execute_query(
        "SELECT id FROM users WHERE email = %s",
        (admin_email,), fetch_one=True
    )
    if not existing:
        from werkzeug.security import generate_password_hash
        ph = generate_password_hash(admin_password, method='pbkdf2:sha256:600000')
        execute_query(
            "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 'admin')",
            (admin_name, admin_email, ph)
        )
        logger.info(f"Default admin account created: {admin_email}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    logger.info("Initializing database schema...")
    init_db_schema()
    logger.info("Setting up admin account...")
    setup_admin()
    logger.info("Starting Digital Signature System on http://localhost:5000")
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=Config.DEBUG
    )
