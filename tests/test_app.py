from fastapi.testclient import TestClient

from app import database
from app.main import app


def test_dashboard_brand_candidate_verdict_and_export(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    with TestClient(app) as client:
        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "Hostname monitoring dashboard" in dashboard.text

        brand_response = client.post(
            "/brands",
            data={"name": "Acme Test", "official_domains": "acme.example", "keywords": "customer"},
            follow_redirects=False,
        )
        assert brand_response.status_code == 303

        candidate_response = client.post(
            "/hosts",
            data={"brand_id": "1", "hostname": "acme-login.provider.example", "source_note": "manual test"},
            follow_redirects=False,
        )
        assert candidate_response.status_code == 303

        detail = client.get("/hosts/1")
        assert detail.status_code == 200
        assert "Score breakdown" in detail.text
        assert "acme-login.provider.example" in detail.text

        verdict = client.post(
            "/hosts/1/verdict",
            data={"verdict": "needs_review", "notes": "Check content evidence"},
            follow_redirects=False,
        )
        assert verdict.status_code == 303
        assert "Check content evidence" in client.get("/hosts/1").text

        export = client.get("/export.csv")
        assert export.status_code == 200
        assert "acme-login.provider.example" in export.text
