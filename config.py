import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'

    # Database
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = int(os.environ.get('DB_PORT', 3306))
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
    DB_NAME = os.environ.get('DB_NAME', 'digital_signature_system')

    # Encryption
    PRIVATE_KEY_ENCRYPTION_KEY = os.environ.get('PRIVATE_KEY_ENCRYPTION_KEY', '')

    # File uploads
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))  # 16MB
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                  os.environ.get('UPLOAD_FOLDER', 'uploads'))
    CERTIFICATES_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        os.environ.get('CERTIFICATES_FOLDER', 'certificates'))
    KEYS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.environ.get('KEYS_FOLDER', 'keys'))
    ALLOWED_EXTENSIONS = {'pdf'}

    # WTF CSRF
    WTF_CSRF_TIME_LIMIT = 3600
