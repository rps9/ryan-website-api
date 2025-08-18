import os
from psycopg_pool import ConnectionPool

DATABASE_URL = os.environ["DATABASE_URL"]

pool = ConnectionPool(conninfo=DATABASE_URL, min_size=1, max_size=5, timeout=10, max_idle=300, max_lifetime=1800, reconnect_timeout=5,
    kwargs={
        "sslmode": "require",
        "connect_timeout": 5,
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 5,
    },
)

def ping() -> bool:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            cur.fetchone()
            return True
