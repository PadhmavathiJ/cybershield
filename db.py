import os
import oracledb
from dotenv import load_dotenv

load_dotenv()
_pool = None

def init_pool():
    global _pool
    if _pool is not None:
        return _pool
    user = os.getenv("ORACLE_USER")
    password = os.getenv("ORACLE_PASSWORD")
    dsn = os.getenv("ORACLE_DSN", "localhost:1521/FREEPDB1")
    if not user or not password:
        raise RuntimeError("Set ORACLE_USER and ORACLE_PASSWORD in .env before starting Flask.")
    _pool = oracledb.create_pool(user=user, password=password, dsn=dsn, min=1, max=5, increment=1)
    return _pool

def get_connection():
    return init_pool().acquire()

def close_pool():
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
