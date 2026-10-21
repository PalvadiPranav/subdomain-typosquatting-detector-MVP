"""Web interface for the Subdomain Typosquatting Detection Platform MVP."""
from __future__ import annotations

import csv
from contextlib import asynccontextmanager
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .database import connect, init_db
from .discovery import discover_ct_candidates
from .normalization import normalize_hostname, registrable_domain
from .scoring import score_hostname

APP_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Subdomain Typosquatting Detection Platform",
    description="Local defensive MVP for CT discovery, explainable triage, analyst verdicts and exports.",
    version="0.1.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

VERDICTS = [
    ("unreviewed", "Unreviewed"),
    ("true_positive", "True positive"),
    ("false_positive", "False positive"),
    ("authorized", "Authorized / legitimate"),
    ("parked", "Parked page"),
    ("needs_review", "Needs more evidence"),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_csvish(value: str) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in (value or "").replace("\n", ",").split(",") if item.strip()))


def brand_from_row(row) -> dict:
    item = dict(row)
    item["official_domains"] = json.loads(item.pop("official_domains_json"))
    item["keywords"] = json.loads(item.pop("keywords_json"))
    return item


def get_brand(db, brand_id: int) -> dict | None:
    row = db.execute("SELECT * FROM brands WHERE id = ?", (brand_id,)).fetchone()
    return brand_from_row(row) if row else None


def save_candidate(db, brand: dict, hostname: str, source: str) -> tuple[int, bool]:
    hostname = normalize_hostname(hostname)
    result = score_hostname(hostname, brand["name"], brand["official_domains"], brand["keywords"], source)
    timestamp = now_iso()
    existing = db.execute("SELECT id FROM hosts WHERE brand_id = ? AND hostname = ?", (brand["id"], hostname)).fetchone()
    if existing:
        db.execute("""UPDATE hosts SET registered_domain=?, source=?, score=?, tier=?, breakdown_json=?,
                    last_seen=?, updated_at=? WHERE id=?""",
                   (result["registered_domain"], source, result["score"], result["tier"],
                    json.dumps(result["signals"]), timestamp, timestamp, existing["id"]))
        return int(existing["id"]), False

    cursor = db.execute("""INSERT INTO hosts
        (brand_id, hostname, registered_domain, source, score, tier, breakdown_json, verdict, notes,
         first_seen, last_seen, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'unreviewed', '', ?, ?, ?)""",
        (brand["id"], hostname, result["registered_domain"], source, result["score"], result["tier"],
         json.dumps(result["signals"]), timestamp, timestamp, timestamp))
    return int(cursor.lastrowid), True


def build_dashboard_data(q: str = "", tier: str = "", verdict: str = "") -> dict:
    with connect() as db:
        brands = [brand_from_row(row) for row in db.execute("SELECT * FROM brands ORDER BY name COLLATE NOCASE").fetchall()]
        where = []
        params: list[str] = []
        if q.strip():
            needle = f"%{q.strip()}%"
            where.append("(h.hostname LIKE ? OR b.name LIKE ? OR h.registered_domain LIKE ?)")
            params.extend([needle, needle, needle])
        if tier in {"high", "review", "low"}:
            where.append("h.tier = ?")
            params.append(tier)
        if verdict in {v[0] for v in VERDICTS}:
            where.append("h.verdict = ?")
            params.append(verdict)
        filter_sql = ("WHERE " + " AND ".join(where)) if where else ""
        hosts = [dict(row) for row in db.execute(f"""
            SELECT h.*, b.name AS brand_name FROM hosts h JOIN brands b ON b.id = h.brand_id
            {filter_sql} ORDER BY h.score DESC, h.last_seen DESC LIMIT 250
        """, params).fetchall()]
        metrics = {
            "brands": db.execute("SELECT COUNT(*) FROM brands").fetchone()[0],
            "hosts": db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0],
            "review": db.execute("SELECT COUNT(*) FROM hosts WHERE verdict='unreviewed' OR verdict='needs_review'").fetchone()[0],
            "high": db.execute("SELECT COUNT(*) FROM hosts WHERE tier='high'").fetchone()[0],
        }
    return {"brands": brands, "hosts": hosts, "metrics": metrics,
            "q": q, "tier": tier, "verdict": verdict, "verdict_options": VERDICTS}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": app.version, "mode": "local-mvp"}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, q: str = "", tier: str = "", verdict: str = "", message: str = "", error: str = ""):
    context = {"request": request, **build_dashboard_data(q, tier, verdict), "message": message, "error": error}
    return templates.TemplateResponse(request=request, name="dashboard.html", context=context)


@app.post("/brands")
def create_brand(name: str = Form(...), official_domains: str = Form(...), keywords: str = Form("")):
    name = name.strip()
    if len(name) < 2 or len(name) > 100:
        return RedirectResponse("/?" + urlencode({"error": "Brand name must be between 2 and 100 characters."}), status_code=303)
    domains = []
    try:
        for domain in parse_csvish(official_domains):
            normalized = normalize_hostname(domain)
            if normalized not in domains:
                domains.append(normalized)
    except ValueError as exc:
        return RedirectResponse("/?" + urlencode({"error": str(exc)}), status_code=303)
    if not domains:
        return RedirectResponse("/?" + urlencode({"error": "Add at least one official domain."}), status_code=303)
    keyword_list = parse_csvish(keywords)
    with connect() as db:
        try:
            db.execute("INSERT INTO brands(name, official_domains_json, keywords_json, created_at) VALUES (?, ?, ?, ?)",
                       (name, json.dumps(domains), json.dumps(keyword_list), now_iso()))
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                return RedirectResponse("/?" + urlencode({"error": f"A brand named '{name}' already exists."}), status_code=303)
            raise
    return RedirectResponse("/?" + urlencode({"message": f"Brand '{name}' added."}), status_code=303)


@app.post("/hosts")
def create_host(brand_id: int = Form(...), hostname: str = Form(...), source_note: str = Form("manual")):
    with connect() as db:
        brand = get_brand(db, brand_id)
        if not brand:
            return RedirectResponse("/?" + urlencode({"error": "Select a valid brand first."}), status_code=303)
        try:
            clean_host = normalize_hostname(hostname)
        except ValueError as exc:
            return RedirectResponse("/?" + urlencode({"error": str(exc)}), status_code=303)
        safe_source = source_note.strip()[:80] or "manual"
        _, created = save_candidate(db, brand, clean_host, safe_source)
    message = "Candidate added and scored." if created else "Candidate already existed; its last-seen time and score were refreshed."
    return RedirectResponse("/?" + urlencode({"message": message}), status_code=303)


@app.post("/brands/{brand_id}/discover")
def discover_brand(brand_id: int):
    with connect() as db:
        brand = get_brand(db, brand_id)
        if not brand:
            return RedirectResponse("/?" + urlencode({"error": "Brand not found."}), status_code=303)
    result = discover_ct_candidates(brand["name"], brand["official_domains"], max_candidates=100)
    created_count = 0
    refreshed_count = 0
    with connect() as db:
        # Re-read because another request might have edited the data while discovery ran.
        current_brand = get_brand(db, brand_id)
        if current_brand:
            for hostname in result["candidates"]:
                try:
                    _, created = save_candidate(db, current_brand, hostname, "CT: crt.sh")
                    created_count += int(created)
                    refreshed_count += int(not created)
                except ValueError:
                    continue
    combined = f"{result['message']} Added {created_count} new; refreshed {refreshed_count} existing candidate(s)."
    return RedirectResponse("/?" + urlencode({"message": combined}), status_code=303)


@app.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_detail(request: Request, host_id: int, message: str = "", error: str = ""):
    with connect() as db:
        row = db.execute("SELECT h.*, b.name AS brand_name, b.official_domains_json, b.keywords_json FROM hosts h JOIN brands b ON b.id=h.brand_id WHERE h.id=?", (host_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Candidate not found")
    host = dict(row)
    host["signals"] = json.loads(host.pop("breakdown_json"))
    host["official_domains"] = json.loads(host.pop("official_domains_json"))
    host.pop("keywords_json", None)
    return templates.TemplateResponse(request=request, name="detail.html", context={
        "request": request, "host": host, "verdict_options": VERDICTS,
        "message": message, "error": error,
    })


@app.post("/hosts/{host_id}/verdict")
def update_verdict(host_id: int, verdict: str = Form(...), notes: str = Form("")):
    allowed = {item[0] for item in VERDICTS}
    if verdict not in allowed:
        return RedirectResponse(f"/hosts/{host_id}?" + urlencode({"error": "Invalid verdict."}), status_code=303)
    with connect() as db:
        exists = db.execute("SELECT id FROM hosts WHERE id=?", (host_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="Candidate not found")
        db.execute("UPDATE hosts SET verdict=?, notes=?, updated_at=? WHERE id=?",
                   (verdict, notes.strip()[:5000], now_iso(), host_id))
    return RedirectResponse(f"/hosts/{host_id}?" + urlencode({"message": "Analyst verdict saved."}), status_code=303)


@app.get("/export.csv")
def export_csv():
    with connect() as db:
        rows = db.execute("""SELECT b.name AS brand, h.hostname, h.registered_domain, h.source, h.score,
            h.tier, h.verdict, h.notes, h.first_seen, h.last_seen, h.updated_at, h.breakdown_json
            FROM hosts h JOIN brands b ON b.id=h.brand_id ORDER BY h.score DESC""").fetchall()
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(["brand", "hostname", "registered_domain", "source", "score", "tier", "verdict", "notes", "first_seen_utc", "last_seen_utc", "updated_at_utc", "signal_breakdown_json"])
    for row in rows:
        writer.writerow(list(row))
    return Response(content=buffer.getvalue(), media_type="text/csv; charset=utf-8",
                     headers={"Content-Disposition": "attachment; filename=typosquatting_findings.csv"})
