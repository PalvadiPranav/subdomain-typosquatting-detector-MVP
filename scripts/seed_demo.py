"""Insert fictional demonstration records for a first run: python scripts/seed_demo.py"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.database import connect, init_db
from app.main import now_iso, save_candidate


def main():
    init_db()
    with connect() as db:
        existing = db.execute("SELECT id FROM brands WHERE name=?", ("Acme Demo",)).fetchone()
        if existing:
            print("Demo brand already exists; skipping seed to avoid duplicates.")
            return
        cursor = db.execute(
            "INSERT INTO brands(name, official_domains_json, keywords_json, created_at) VALUES (?, ?, ?, ?)",
            ("Acme Demo", '["acme.example"]', '["customer portal"]', now_iso()),
        )
        brand_id = int(cursor.lastrowid)
        brand = {"id": brand_id, "name": "Acme Demo", "official_domains": ["acme.example"], "keywords": ["customer portal"]}
        examples = [
            ("acme-login.provider.example", "manual demo (fictional)",),
            ("portal.acme.example", "manual demo (official-domain control)"),
            ("acne-secure.pages.example", "manual demo (near-match control)"),
        ]
        for hostname, source in examples:
            save_candidate(db, brand, hostname, source)
    print("Inserted fictional Acme Demo brand and 3 example candidates.")
    print("These are sample data only; they are not claims about real websites.")


if __name__ == "__main__":
    main()
