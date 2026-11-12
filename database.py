import mysql.connector
from mysql.connector import pooling
from config import Config
import logging

logger = logging.getLogger(__name__)

# Connection pool
_pool = None

def get_pool():
    global _pool
    if _pool is None:
        _pool = pooling.MySQLConnectionPool(
            pool_name="dss_pool",
            pool_size=5,
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            autocommit=False,
            charset='utf8mb4',
            collation='utf8mb4_unicode_ci'
        )
    return _pool

def get_db():
    """Get a connection from the pool."""
    return get_pool().get_connection()

def execute_query(query, params=None, fetch=False, fetch_one=False, lastrowid=False):
    """Execute a parameterized query safely."""
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(query, params or ())
        if fetch_one:
            result = cursor.fetchone()
            conn.commit()
            return result
        if fetch:
            result = cursor.fetchall()
            conn.commit()
            return result
        conn.commit()
        if lastrowid:
            return cursor.lastrowid
        return cursor.rowcount
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        cursor.close()
        conn.close()

def init_db_schema():
    """Initialize the database schema."""
    # Read and execute schema
    import os
    schema_path = os.path.join(os.path.dirname(__file__), 'database', 'schema.sql')
    with open(schema_path, 'r') as f:
        schema_sql = f.read()
    
    # Connect without database to create it
    conn = mysql.connector.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        charset='utf8mb4'
    )
    cursor = conn.cursor()
    
    # Execute statements one by one
    statements = [s.strip() for s in schema_sql.split(';') if s.strip()]
    for stmt in statements:
        try:
            cursor.execute(stmt)
            conn.commit()
        except mysql.connector.Error as e:
            if e.errno == 1050:  # Table already exists
                pass
            elif e.errno == 1007:  # Database already exists
                pass
            else:
                logger.warning(f"Schema statement warning: {e}")
    cursor.close()
    conn.close()
    logger.info("Database schema initialized successfully.")
