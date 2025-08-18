import os
from psycopg_pool import ConnectionPool
from contextlib import contextmanager
from psycopg.errors import OperationalError, InterfaceError

DATABASE_URL = os.environ["DATABASE_URL"]

pool = ConnectionPool(conninfo=DATABASE_URL, min_size=1, max_size=5, timeout=10, check=ConnectionPool.check_connection)

def ping() -> bool:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            cur.fetchone()
            return True