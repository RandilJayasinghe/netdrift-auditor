from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netdrift.api.main import app

FIX = Path(__file__).parent / "fixtures"
PROFILE = (FIX / "profile.json").read_text()


@pytest.fixture()
def client():
    return TestClient(app)


def _upload(client, name="bank_hq_sonicwall.conf"):
    r = client.post("/api/v1/audit/upload", files={"file": (name, (FIX / name).read_bytes())})
    assert r.status_code == 201, r.text
    return r.json()


def test_full_flow(client):
    up = _upload(client)
    assert up["vendor"] == "sonicwall" and up["rules"] == 10
    import json
    res = client.post("/api/v1/audit/analyze", json={"config_id": up["config_id"], "profile": json.loads(PROFILE)})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["score"]["grade"] in ("D", "F") and body["attack_paths"]
    cy = client.get("/api/v1/reports/attack-paths", params={"audit_id": body["audit_id"]}).json()
    assert cy["elements"]["nodes"] and any("attack" in (e["classes"] or "") for e in cy["elements"]["edges"])
    md = client.get("/api/v1/reports/summary", params={"audit_id": body["audit_id"], "format": "markdown"})
    assert md.status_code == 200 and "NetDrift-Auditor Report" in md.text
    pdf = client.get("/api/v1/reports/summary", params={"audit_id": body["audit_id"], "format": "pdf"})
    assert pdf.content[:4] == b"%PDF"


def test_errors(client):
    assert client.post("/api/v1/audit/upload", files={"file": ("x.conf", b"nonsense")}).status_code == 422
    assert client.get("/api/v1/reports/attack-paths", params={"audit_id": "nope"}).status_code == 404
    assert client.post("/api/v1/audit/analyze", json={"config_id": "nope", "profile": {"entry_points": ["LAN"], "critical_assets": [{"name": "a", "cidr": "10.0.0.1/32"}]}}).status_code == 404


def test_api_key_enforced(client, monkeypatch):
    monkeypatch.setenv("NETDRIFT_API_KEY", "s3cret")
    assert client.get("/api/v1/reports/summary", params={"audit_id": "x"}).status_code == 401
    assert client.get("/api/v1/reports/summary", params={"audit_id": "x"}, headers={"X-API-Key": "s3cret"}).status_code == 404
