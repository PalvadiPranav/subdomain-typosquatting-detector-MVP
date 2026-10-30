"""SQLite persistence for the local MVP."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("APP_DB_PATH", str(ROOT / "data" / "app.db")))


class ManagedConnection(sqlite3.Connection):
    """Connection context manager that commits/rolls back and always closes."""
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10, factory=ManagedConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS brands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            official_domains_json TEXT NOT NULL,
            keywords_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            brand_id INTEGER NOT NULL REFERENCES brands(id) ON DELETE CASCADE,
            hostname TEXT NOT NULL,
            registered_domain TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'manual',
            score INTEGER NOT NULL DEFAULT 0,
            tier TEXT NOT NULL DEFAULT 'low',
            scoring_version TEXT NOT NULL DEFAULT '0.2.0',
            breakdown_json TEXT NOT NULL DEFAULT '[]',
            verdict TEXT NOT NULL DEFAULT 'unreviewed',
            notes TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(brand_id, hostname)
        );
        CREATE INDEX IF NOT EXISTS idx_hosts_score ON hosts(score DESC);
        CREATE INDEX IF NOT EXISTS idx_hosts_brand ON hosts(brand_id);
        CREATE INDEX IF NOT EXISTS idx_hosts_verdict ON hosts(verdict);

        CREATE TABLE IF NOT EXISTS enrichment_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            fetched_at TEXT NOT NULL,
            source_summary TEXT NOT NULL,
            dns_json TEXT NOT NULL,
            tls_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_enrichment_host_fetched
            ON enrichment_runs(host_id, fetched_at DESC);
        """)
        # Small, safe migration for databases created by the v0.2.0 release.
        # Existing findings are re-scored by the app lifespan when the model version changes.
        host_columns = {row["name"] for row in db.execute("PRAGMA table_info(hosts)").fetchall()}
        if "scoring_version" not in host_columns:
            db.execute("ALTER TABLE hosts ADD COLUMN scoring_version TEXT NOT NULL DEFAULT '0.2.0'")
