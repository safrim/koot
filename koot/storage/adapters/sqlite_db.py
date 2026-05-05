# koot/storage/adapters/sqlite_db.py
import sqlite3
from typing import Optional
from .base import StorageDriver

class SQLiteAdapter(StorageDriver):
    """
    Storage adapter that saves chunks/envelopes into an SQLite database.
    Ideal for portable, single-file vault implementations.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # We treat the data as a BLOB
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS koot_storage (
                    key TEXT PRIMARY KEY,
                    payload BLOB NOT NULL
                )
            """)
            conn.commit()

    def write(self, key: str, data: bytes) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO koot_storage (key, payload) VALUES (?, ?)", 
                    (key, data)
                )
                conn.commit()
            return True
        except sqlite3.Error:
            return False

    def read(self, key: str) -> Optional[bytes]:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT payload FROM koot_storage WHERE key = ?", (key,))
                row = cursor.fetchone()
                return row[0] if row else None
        except sqlite3.Error:
            return None

    def delete(self, key: str) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM koot_storage WHERE key = ?", (key,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def exists(self, key: str) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM koot_storage WHERE key = ?", (key,))
                return cursor.fetchone() is not None
        except sqlite3.Error:
            return False