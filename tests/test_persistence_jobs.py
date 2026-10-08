"""Database persistence, baselines/drift, tenant isolation, async jobs and secret hygiene."""
import json
import logging
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from netdrift.api.db import ConfigRow, FindingRow
from netdrift.api.main import create_app
from netdrift.api.settings import Settings
from netdrift.errors import SecretLeakError
from netdrift.parsers import parse_config
from netdrift.sanitizer import SanitizedConfig, sanitize_for_storage

from conftest import FIX

PROFILE = json.loads((FIX / "profile.json").read_text())
SONIC = (FIX / "bank_hq_sonicwall.conf").read_bytes()


def make_app(tmp_path, **kw):
    s = Settings(database_url=f"sqlite:///{tmp_path / 'nd.db'}", async_workers=kw.pop("async_workers", 2), **kw)
    return create_app(s)


def upload(c, data=SONIC, name="c.conf", **kw):
    r = c.post("/api/v1/audit/upload", files={"file": (name, data)}, **kw)
    assert r.status_code == 201, r.text
    return r.json()


def wait_job(c, job_id, timeout=30, **kw):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        j = c.get(f"/api/v1/audit/jobs/{job_id}", **kw).json()
        if j["status"] in ("succeeded", "failed"):
            return j
        time.sleep(0.05)
    raise AssertionError("job did not finish")


# ---- persistence ------------------------------------------------------------------------------
def test_data_survives_restart(tmp_path):
    with TestClient(make_app(tmp_path)) as c:
        cid = upload(c)["config_id"]
        audit = c.post("/api/v1/audit/analyze", json={"config_id": cid, "profile": PROFILE}).json()
    # brand new application object on the same database file == process restart
    with TestClient(make_app(tmp_path)) as c2:
        assert [x["config_id"] for x in c2.get("/api/v1/configs").json()] == [cid]
        again = c2.get("/api/v1/reports/summary", params={"audit_id": audit["audit_id"], "format": "json"}).json()
        assert again["score"] == audit["score"] and len(again["findings"]) == len(audit["findings"])
        cy = c2.get("/api/v1/reports/attack-paths", params={"audit_id": audit["audit_id"]}).json()  # graph rebuilt from DB
        assert cy["elements"]["nodes"] and cy["paths"]
        assert c2.get("/api/v1/reports/summary", params={"audit_id": audit["audit_id"], "format": "pdf"}).content[:4] == b"%PDF"


def test_findings_are_rows_and_queryable(tmp_path):
    app = make_app(tmp_path)
    with TestClient(app) as c:
        cid = upload(c)["config_id"]
        a = c.post("/api/v1/audit/analyze", json={"config_id": cid, "profile": PROFILE}).json()
        crit = c.get(f"/api/v1/audit/{a['audit_id']}/findings", params={"severity": "critical"}).json()
        assert crit and all(f["severity"] == "critical" for f in crit)
        shadows = c.get(f"/api/v1/audit/{a['audit_id']}/findings", params={"category": "SHADOWED_RULE"}).json()
        assert [f["rule_ids"] for f in shadows] == [["R6", "R5"]]
        assert c.get("/api/v1/audit/nope/findings").status_code == 404
        with app.state.store.session() as s:
            assert len(s.scalars(select(FindingRow).where(FindingRow.audit_id == a["audit_id"])).all()) == len(a["findings"])


def test_baseline_snapshot_drift_and_cascade_delete(tmp_path):
    with TestClient(make_app(tmp_path)) as c:
        base = upload(c)["config_id"]
        drifted = SONIC.replace(b'action allow', b'action allow', 1) + b'\naccess-rule ipv4 from WAN to LAN action allow source address any service any destination address any\n'
        cur = upload(c, drifted)["config_id"]
        b = c.post("/api/v1/baselines", json={"name": "golden-2026-10", "config_id": base}).json()
        assert c.get("/api/v1/baselines").json()[0]["baseline_id"] == b["baseline_id"]
        a = c.post("/api/v1/audit/analyze", json={"config_id": cur, "profile": PROFILE, "baseline_id": b["baseline_id"]}).json()
        assert a["drift"] and a["drift"]["added"]
        assert any(f["category"] == "POLICY_DRIFT" for f in a["findings"])
        assert c.post("/api/v1/baselines", json={"name": "x", "config_id": "nope"}).status_code == 404
        assert c.post("/api/v1/audit/analyze", json={"config_id": cur, "profile": PROFILE, "baseline_id": "nope"}).status_code == 404
        assert c.delete(f"/api/v1/configs/{cur}").status_code == 204          # takes its audits + findings with it
        assert c.get("/api/v1/reports/summary", params={"audit_id": a["audit_id"], "format": "json"}).status_code == 404
        assert c.delete(f"/api/v1/configs/{cur}").status_code == 404


# ---- jobs -------------------------------------------------------------------------------------
def test_async_job_lifecycle_and_polling(tmp_path):
    with TestClient(make_app(tmp_path)) as c:
        cid = upload(c)["config_id"]
        r = c.post("/api/v1/audit/jobs", json={"config_id": cid, "profile": PROFILE})
        assert r.status_code in (200, 202) and r.json()["poll_url"].endswith(r.json()["job_id"])
        jid = r.json()["job_id"]
        done = wait_job(c, jid)
        assert done["status"] == "succeeded" and done["audit_id"] and done["finished_at"] and done["error"] is None
        res = c.get(done["result_url"]).json()
        assert res["audit_id"] == done["audit_id"] and res["attack_paths"]
        assert c.get("/api/v1/audit/jobs/nope").status_code == 404


def test_job_failure_is_recorded_not_raised(tmp_path):
    with TestClient(make_app(tmp_path)) as c:
        cid = upload(c)["config_id"]
        bad = {**PROFILE, "entry_points": ["no-such-zone"]}
        jid = c.post("/api/v1/audit/jobs", json={"config_id": cid, "profile": bad}).json()["job_id"]
        j = wait_job(c, jid)
        assert j["status"] == "failed" and "no-such-zone" in j["error"] and j["audit_id"] is None
        assert c.post("/api/v1/audit/jobs", json={"config_id": "nope", "profile": PROFILE}).status_code == 404


def test_synchronous_fallbacks(tmp_path):
    # workers=0: the job runs inline and the very first response is already final
    with TestClient(make_app(tmp_path, async_workers=0)) as c:
        cid = upload(c)["config_id"]
        r = c.post("/api/v1/audit/jobs", json={"config_id": cid, "profile": PROFILE})
        assert r.status_code == 200 and r.json()["status"] == "succeeded"
    # ?wait=true on a threaded service blocks until done
    with TestClient(make_app(tmp_path)) as c:
        cid = upload(c)["config_id"]
        r = c.post("/api/v1/audit/jobs", params={"wait": "true"}, json={"config_id": cid, "profile": PROFILE})
        assert r.status_code == 200 and r.json()["status"] == "succeeded"


def test_interrupted_jobs_are_failed_on_restart(tmp_path):
    app = make_app(tmp_path, async_workers=0)
    with TestClient(app) as c:
        cid = upload(c)["config_id"]
        from netdrift.schemas import AuditProfile
        jid = app.state.store.create_job("default", cid, None, AuditProfile.model_validate(PROFILE))  # queued, never run
        app.state.store.mark_job(jid, "running")
    with TestClient(make_app(tmp_path, async_workers=0)) as c2:
        j = c2.get(f"/api/v1/audit/jobs/{jid}").json()
        assert j["status"] == "failed" and "restart" in j["error"]


# ---- secrets never persisted or logged ---------------------------------------------------------
FORTI_SECRETS = b"""config system global
    set hostname "FGT-S"
end
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.248
        set role wan
    next
end
config vpn ipsec phase1-interface
    edit "to-hq"
        set psksecret ENC AAAABBBBCCCCDDDDEEEEFFFF1234567890==
    next
end
config system admin
    edit "admin"
        set password ENC SH2zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz==
    next
end
config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set comments "contact admin password hunter2secret"
    next
end
"""


def test_secrets_are_stripped_before_persist_and_never_logged(tmp_path, caplog):
    app = make_app(tmp_path)
    secrets = ["AAAABBBBCCCCDDDDEEEEFFFF1234567890", "SH2zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "hunter2secret"]
    with caplog.at_level(logging.DEBUG, logger="netdrift"), TestClient(app) as c:
        up = upload(c, FORTI_SECRETS)
        assert up["redactions"] >= 3
        logging.getLogger("netdrift.test").info("debug dump: set password ENC %s", "SH2qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq==")
        cid = up["config_id"]
        c.post("/api/v1/audit/analyze", json={"config_id": cid, "profile": {"entry_points": ["wan1"], "critical_assets": [{"name": "a", "cidr": "203.0.113.3/32"}]}})
        with app.state.store.session() as s:
            row = s.scalar(select(ConfigRow).where(ConfigRow.id == cid))
            blob = row.sanitized_text + row.config_json
            raw_db = " ".join(str(x) for r in s.execute(text("select * from configs")).fetchall() for x in r)
    for sec in secrets + ["SH2qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"]:
        assert sec not in blob and sec not in raw_db and sec not in caplog.text, sec
    assert "[REDACTED_SECRET]" in blob and "FGT-S" in blob  # structure survives, secrets do not


def test_store_refuses_unsanitized_text(tmp_path):
    store = make_app(tmp_path).state.store
    cfg = parse_config(SONIC.decode())
    leaky = SanitizedConfig("set password ENC SH2zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz==", "0" * 64, 0)  # claims to be clean, is not
    with pytest.raises(SecretLeakError):
        store.put_config("default", cfg, leaky)
    with pytest.raises(SecretLeakError):
        store.put_config("default", cfg, "raw text")  # type: ignore[arg-type]
    with pytest.raises(SecretLeakError):
        cfg2 = cfg.model_copy(update={"hostname": "x", "warnings": ['"password": "plaintext-value"']})
        store.put_config("default", cfg2, sanitize_for_storage("hostname x"))   # secret smuggled in via parsed model
    assert store.list_configs("default") == []


def test_sanitizer_covers_fortios_and_json_forms():
    from netdrift.sanitizer import sanitize_config, verify_sanitized
    out = sanitize_config('set psksecret ENC QWERTYUIOPASDFGHJKL==\nset password ENC SH2abcdefabcdefabcdef==\n{"password": "x", "token": "y", "ok": "z"}')
    assert "QWERTY" not in out and "SH2abc" not in out and '"x"' not in out and '"y"' not in out and '"ok": "z"' in out
    assert sanitize_config(out) == out        # idempotent: output is a fixed point
    verify_sanitized(out)
