"""Authentication, RBAC / multi-tenancy, JWT, rate limiting and payload size limits."""
import hashlib
import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from netdrift.api.main import create_app
from netdrift.api.security import RateLimiter, issue_token, parse_rate
from netdrift.api.settings import Settings

from conftest import FIX

PROFILE = json.loads((FIX / "profile.json").read_text())
SONIC = (FIX / "bank_hq_sonicwall.conf").read_bytes()
SECRET = "unit-test-secret-unit-test-secret-0123456789"


def app_for(tmp_path, **kw):
    kw.setdefault("rate_limit", "10000/minute")
    kw.setdefault("rate_limit_heavy", "10000/minute")
    kw.setdefault("auth_fail_limit", "10000/minute")
    return create_app(Settings(database_url=f"sqlite:///{tmp_path / 's.db'}", async_workers=0, **kw))


def keys_env(monkeypatch):
    sha = lambda k: hashlib.sha256(k.encode()).hexdigest()  # noqa: E731
    monkeypatch.setenv("NETDRIFT_API_KEYS", json.dumps([
        {"name": "ro", "tenant": "acme", "role": "viewer", "key_sha256": sha("ro-key")},
        {"name": "ci", "tenant": "acme", "role": "analyst", "key_sha256": sha("ci-key")},
        {"name": "boss", "tenant": "acme", "role": "admin", "key_sha256": sha("boss-key")},
        {"name": "other", "tenant": "globex", "role": "admin", "key": "globex-key"},
    ]))


def H(k):
    return {"X-API-Key": k}


def up(c, key):
    return c.post("/api/v1/audit/upload", files={"file": ("c.conf", SONIC)}, headers=H(key))


# ---- RBAC + tenancy ---------------------------------------------------------------------------
def test_rbac_matrix(tmp_path, monkeypatch):
    keys_env(monkeypatch)
    with TestClient(app_for(tmp_path)) as c:
        assert c.get("/api/v1/configs").status_code == 401
        assert c.get("/api/v1/configs", headers=H("wrong")).status_code == 401
        assert c.get("/health").status_code == 200                           # liveness stays open
        assert up(c, "ro-key").status_code == 403                            # viewer cannot upload
        r = up(c, "ci-key")
        assert r.status_code == 201
        cid = r.json()["config_id"]
        assert c.get("/api/v1/configs", headers=H("ro-key")).status_code == 200
        body = {"config_id": cid, "profile": PROFILE}
        assert c.post("/api/v1/audit/analyze", json=body, headers=H("ro-key")).status_code == 403
        assert c.post("/api/v1/audit/analyze", json=body, headers=H("ci-key")).status_code == 200
        assert c.delete(f"/api/v1/configs/{cid}", headers=H("ci-key")).status_code == 403   # analyst cannot delete
        assert c.delete(f"/api/v1/configs/{cid}", headers=H("boss-key")).status_code == 204


def test_tenants_cannot_see_each_other(tmp_path, monkeypatch):
    keys_env(monkeypatch)
    with TestClient(app_for(tmp_path)) as c:
        cid = up(c, "ci-key").json()["config_id"]
        a = c.post("/api/v1/audit/analyze", json={"config_id": cid, "profile": PROFILE}, headers=H("ci-key")).json()
        j = c.post("/api/v1/audit/jobs", json={"config_id": cid, "profile": PROFILE}, headers=H("ci-key")).json()
        # the other tenant gets 404s (indistinguishable from "does not exist"), and an empty listing
        assert c.get("/api/v1/configs", headers=H("globex-key")).json() == []
        assert c.post("/api/v1/audit/analyze", json={"config_id": cid, "profile": PROFILE}, headers=H("globex-key")).status_code == 404
        assert c.get("/api/v1/reports/summary", params={"audit_id": a["audit_id"]}, headers=H("globex-key")).status_code == 404
        assert c.get(f"/api/v1/audit/jobs/{j['job_id']}", headers=H("globex-key")).status_code == 404
        assert c.get(f"/api/v1/audit/{a['audit_id']}/findings", headers=H("globex-key")).status_code == 404
        assert c.delete(f"/api/v1/configs/{cid}", headers=H("globex-key")).status_code == 404
        assert c.get(f"/api/v1/audit/jobs/{j['job_id']}", headers=H("ro-key")).status_code == 200  # same tenant


def test_legacy_single_key(tmp_path, monkeypatch):
    monkeypatch.setenv("NETDRIFT_API_KEY", "s3cret")
    with TestClient(app_for(tmp_path)) as c:
        assert c.get("/api/v1/configs").status_code == 401
        assert c.get("/api/v1/configs", headers=H("s3cret")).status_code == 200


def test_open_mode_and_require_auth(tmp_path, monkeypatch):
    for v in ("NETDRIFT_API_KEY", "NETDRIFT_API_KEYS", "NETDRIFT_JWT_SECRET"):
        monkeypatch.delenv(v, raising=False)
    with TestClient(app_for(tmp_path)) as c:
        assert c.get("/api/v1/configs").status_code == 200  # dev mode
    with pytest.raises(RuntimeError, match="REQUIRE_AUTH"):
        app_for(tmp_path, require_auth=True)
    monkeypatch.setenv("NETDRIFT_API_KEY", "k")
    app_for(tmp_path, require_auth=True)  # fine once a credential exists


def test_bad_api_key_config_fails_loudly(tmp_path, monkeypatch):
    monkeypatch.setenv("NETDRIFT_API_KEYS", json.dumps([{"name": "x", "role": "god", "key": "k"}]))
    with pytest.raises(RuntimeError, match="role"):  # surfaces at start-up, not on the first request
        with TestClient(app_for(tmp_path)):
            pass


# ---- JWT --------------------------------------------------------------------------------------
def test_jwt_roles_tenant_and_rejections(tmp_path, monkeypatch):
    monkeypatch.setenv("NETDRIFT_JWT_SECRET", SECRET)
    monkeypatch.delenv("NETDRIFT_API_KEYS", raising=False)
    monkeypatch.delenv("NETDRIFT_API_KEY", raising=False)
    bearer = lambda t: {"Authorization": f"Bearer {t}"}  # noqa: E731
    with TestClient(app_for(tmp_path)) as c:
        viewer = issue_token("alice", tenant="acme", role="viewer")
        analyst = issue_token("bob", tenant="acme", role="analyst")
        assert c.get("/api/v1/configs", headers=bearer(viewer)).status_code == 200
        assert c.post("/api/v1/audit/upload", files={"file": ("c.conf", SONIC)}, headers=bearer(viewer)).status_code == 403
        r = c.post("/api/v1/audit/upload", files={"file": ("c.conf", SONIC)}, headers=bearer(analyst))
        assert r.status_code == 201
        # same tenant claim sees it; different tenant claim does not
        assert len(c.get("/api/v1/configs", headers=bearer(viewer)).json()) == 1
        assert c.get("/api/v1/configs", headers=bearer(issue_token("eve", tenant="evil"))).json() == []
        # rejections
        assert c.get("/api/v1/configs", headers=bearer(issue_token("a", ttl_seconds=-10))).status_code == 401           # expired
        assert c.get("/api/v1/configs", headers=bearer(issue_token("a", secret="x" * 40))).status_code == 401           # bad signature
        assert c.get("/api/v1/configs", headers=bearer(jwt.encode({"sub": "a"}, SECRET, "HS256"))).status_code == 401   # no exp
        assert c.get("/api/v1/configs", headers=bearer(jwt.encode({"exp": time.time() + 99}, SECRET, "HS256"))).status_code == 401  # no sub
        none_tok = jwt.encode({"sub": "a", "exp": time.time() + 99, "role": "admin"}, None, algorithm="none")
        assert c.get("/api/v1/configs", headers=bearer(none_tok)).status_code == 401                                    # alg=none
        bad_role = jwt.encode({"sub": "a", "exp": time.time() + 99, "role": "root"}, SECRET, "HS256")
        assert c.get("/api/v1/configs", headers=bearer(bad_role)).status_code == 401
        assert c.get("/api/v1/configs", headers=bearer("garbage")).status_code == 401


def test_jwt_issuer_and_audience_enforced(tmp_path, monkeypatch):
    monkeypatch.setenv("NETDRIFT_JWT_SECRET", SECRET)
    monkeypatch.setenv("NETDRIFT_JWT_ISSUER", "https://idp.example")
    monkeypatch.setenv("NETDRIFT_JWT_AUDIENCE", "netdrift")
    good = issue_token("a")
    monkeypatch.setenv("NETDRIFT_JWT_AUDIENCE", "someone-else")
    with TestClient(app_for(tmp_path)) as c:
        assert c.get("/api/v1/configs", headers={"Authorization": f"Bearer {good}"}).status_code == 401
        monkeypatch.setenv("NETDRIFT_JWT_AUDIENCE", "netdrift")
        assert c.get("/api/v1/configs", headers={"Authorization": f"Bearer {good}"}).status_code == 200


# ---- rate limiting ----------------------------------------------------------------------------
def test_token_bucket_math():
    now = [0.0]
    rl = RateLimiter("2/second", clock=lambda: now[0])
    assert rl.take("k") == 0 and rl.take("k") == 0
    wait = rl.take("k")
    assert 0.4 < wait <= 0.5                       # 2 tokens/s -> next token in ~0.5s
    assert rl.take("other") == 0                   # buckets are per key
    now[0] += 0.5
    assert rl.take("k") == 0 and rl.take("k") > 0  # refilled by exactly one token
    assert parse_rate("120/minute") == (120, 60.0)


def test_rate_limit_returns_429_with_retry_after(tmp_path, monkeypatch):
    monkeypatch.delenv("NETDRIFT_API_KEY", raising=False)
    monkeypatch.delenv("NETDRIFT_API_KEYS", raising=False)
    monkeypatch.delenv("NETDRIFT_JWT_SECRET", raising=False)
    with TestClient(app_for(tmp_path, rate_limit="3/minute")) as c:
        assert [c.get("/api/v1/configs").status_code for _ in range(3)] == [200, 200, 200]
        r = c.get("/api/v1/configs")
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
        assert c.get("/health").status_code == 200  # health is not rate limited


def test_heavy_endpoints_have_their_own_tighter_budget(tmp_path, monkeypatch):
    monkeypatch.delenv("NETDRIFT_API_KEY", raising=False)
    monkeypatch.delenv("NETDRIFT_API_KEYS", raising=False)
    with TestClient(app_for(tmp_path, rate_limit_heavy="2/minute")) as c:
        assert up(c, "x").status_code == 201 and up(c, "x").status_code == 201
        assert up(c, "x").status_code == 429
        assert c.get("/api/v1/configs").status_code == 200  # cheap reads unaffected


def test_rate_limit_is_per_principal(tmp_path, monkeypatch):
    keys_env(monkeypatch)
    with TestClient(app_for(tmp_path, rate_limit="2/minute")) as c:
        assert [c.get("/api/v1/configs", headers=H("ro-key")).status_code for _ in range(3)] == [200, 200, 429]
        assert c.get("/api/v1/configs", headers=H("boss-key")).status_code == 200  # another principal has its own bucket


def test_failed_auth_attempts_are_throttled(tmp_path, monkeypatch):
    keys_env(monkeypatch)
    with TestClient(app_for(tmp_path, auth_fail_limit="3/minute")) as c:
        codes = [c.get("/api/v1/configs", headers=H(f"guess-{i}")).status_code for i in range(5)]
        assert codes == [401, 401, 401, 429, 429]


# ---- payload size -----------------------------------------------------------------------------
def test_upload_size_limit(tmp_path, monkeypatch):
    monkeypatch.delenv("NETDRIFT_API_KEY", raising=False)
    monkeypatch.delenv("NETDRIFT_API_KEYS", raising=False)
    with TestClient(app_for(tmp_path, max_upload_bytes=2000)) as c:
        r = c.post("/api/v1/audit/upload", files={"file": ("big.conf", b"x" * (2000 + 70 * 1024))})
        assert r.status_code == 413
        assert c.get("/api/v1/configs").json() == []
        assert c.post("/api/v1/audit/upload", files={"file": ("e.conf", b"  \n")}).status_code == 422
        assert c.post("/api/v1/audit/upload", files={"file": ("b.bin", b"\x00\x01\x02" * 50)}).status_code == 415


def test_json_body_limit_declared_and_streamed(tmp_path, monkeypatch):
    monkeypatch.delenv("NETDRIFT_API_KEY", raising=False)
    monkeypatch.delenv("NETDRIFT_API_KEYS", raising=False)
    with TestClient(app_for(tmp_path, max_json_bytes=500)) as c:
        big = json.dumps({"config_id": "x", "profile": PROFILE, "pad": "y" * 600})
        assert c.post("/api/v1/audit/analyze", content=big, headers={"content-type": "application/json"}).status_code == 413

        def chunks():  # no Content-Length: counted while streaming
            for _ in range(10):
                yield b" " * 100

        r = c.post("/api/v1/audit/analyze", content=chunks(), headers={"content-type": "application/json"})
        assert r.status_code == 413
        small = c.post("/api/v1/audit/analyze", json={"config_id": "nope", "profile": PROFILE})
        assert small.status_code == 404  # under the limit: reaches the handler
