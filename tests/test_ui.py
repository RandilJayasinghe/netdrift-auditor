"""Web dashboard: served without auth, static mount works, API unaffected."""
import json

from fastapi.testclient import TestClient

from netdrift.api.main import STATIC_DIR, create_app
from netdrift.api.settings import Settings

from conftest import FIX


def client(tmp_path):
    return TestClient(create_app(Settings(database_url=f"sqlite:///{tmp_path / 'ui.db'}", async_workers=0)))


def test_root_serves_dashboard(tmp_path):
    with client(tmp_path) as c:
        r = c.get("/")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
        for marker in ("NetDrift Auditor", 'id="cy"', "cytoscape", "tailwindcss", "Run Audit", "/api/v1/audit/upload"):
            assert marker in r.text
        assert "/" not in c.get("/openapi.json").json()["paths"]


def test_static_mount(tmp_path):
    assert (STATIC_DIR / "index.html").is_file()
    with client(tmp_path) as c:
        r = c.get("/static/index.html")
        assert r.status_code == 200 and "text/html" in r.headers["content-type"]
        assert c.get("/static/missing.js").status_code == 404
        assert c.get("/static/../main.py").status_code in (400, 404)  # no traversal out of the directory


def test_dashboard_loads_when_auth_is_enabled_but_api_stays_protected(tmp_path, monkeypatch):
    monkeypatch.setenv("NETDRIFT_API_KEY", "k")
    with client(tmp_path) as c:
        assert c.get("/").status_code == 200 and c.get("/static/index.html").status_code == 200
        assert c.get("/api/v1/configs").status_code == 401
        assert c.get("/api/v1/configs", headers={"X-API-Key": "k"}).status_code == 200


def test_api_flow_the_dashboard_performs(tmp_path):
    """Same sequence as the page: upload -> analyze -> cytoscape -> markdown/pdf."""
    prof = json.loads((FIX / "profile.json").read_text())
    with client(tmp_path) as c:
        up = c.post("/api/v1/audit/upload", files={"file": ("a.conf", (FIX / "bank_hq_sonicwall.conf").read_bytes())}, data={"vendor": "sonicwall"})
        assert up.status_code == 201
        res = c.post("/api/v1/audit/analyze", json={"config_id": up.json()["config_id"], "profile": prof}).json()
        cy = c.get("/api/v1/reports/attack-paths", params={"format": "cytoscape", "audit_id": res["audit_id"]}).json()
        assert cy["elements"]["nodes"] and any("attack" in (e["classes"] or "") for e in cy["elements"]["edges"])
        assert c.get("/api/v1/reports/summary", params={"format": "markdown", "audit_id": res["audit_id"]}).status_code == 200
        assert c.get("/api/v1/reports/summary", params={"format": "pdf", "audit_id": res["audit_id"]}).content[:4] == b"%PDF"
        assert c.get("/health").json()["status"] == "ok"
