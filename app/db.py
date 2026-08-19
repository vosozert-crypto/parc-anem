import os

try:
    import psycopg2
    import psycopg2.extras
    _HAS_PG = True
except ImportError:
    _HAS_PG = False


class DBWrapper:
    """Wrapper qui traduit automatiquement les placeholders SQLite (?) en PostgreSQL (%s)."""

    def __init__(self, conn, is_pg):
        self._conn = conn
        self._is_pg = is_pg

    def execute(self, sql, params=()):
        if self._is_pg:
            sql = self._adapt_sql(sql)
        cur = self._conn.cursor()
        cur.execute(sql, params)
        return cur

    def executemany(self, sql, params_list):
        if self._is_pg:
            sql = self._adapt_sql(sql)
        cur = self._conn.cursor()
        cur.executemany(sql, params_list)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def _adapt_sql(self, sql):
        sql = sql.replace("?", "%s")
        sql = sql.replace(
            "GROUP_CONCAT(", "STRING_AGG("
        )
        sql = sql.replace(
            "GROUP_CONCAT(nom, ', ')",
            "STRING_AGG(nom, ', ')"
        )
        sql = sql.replace(
            "GROUP_CONCAT(c.designation, ', ')",
            "STRING_AGG(c.designation, ', ')"
        )
        sql = sql.replace(
            "GROUP_CONCAT(r.nom, ', ')",
            "STRING_AGG(r.nom, ', ')"
        )
        sql = sql.replace(
            "COLLATE NOCASE",
            ""
        )
        sql = sql.replace("datetime('now')", "CURRENT_TIMESTAMP")
        sql = sql.replace('datetime("now")', "CURRENT_TIMESTAMP")
        return sql


def get_connection():
    database_url = os.environ.get("DATABASE_URL")
    if database_url and _HAS_PG:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        if "sslmode=" not in database_url:
            separator = "&" if "?" in database_url else "?"
            database_url += separator + "sslmode=require"
        conn = psycopg2.connect(
            database_url,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        conn.autocommit = False
        return DBWrapper(conn, is_pg=True)
    else:
        import sqlite3
        from app import DB_PATH

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return DBWrapper(conn, is_pg=False)
