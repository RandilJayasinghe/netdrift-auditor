"""Authentication, RBAC, rate limiting and request-size enforcement.

Authentication (first match wins, configured through the environment and re-read per request):

* ``Authorization: Bearer <JWT>``  - ``NETDRIFT_JWT_SECRET`` (HS256) or ``NETDRIFT_JWT_PUBLIC_KEY`` with
  ``NETDRIFT_JWT_ALGORITHM`` (e.g. RS256, needs ``cryptography``). ``exp`` and ``sub`` are required; ``tenant``
  and ``role`` claims select the tenant and RBAC role. Optional ``NETDRIFT_JWT_ISSUER`` / ``NETDRIFT_JWT_AUDIENCE``.
* ``X-API-Key``  - ``NETDRIFT_API_KEYS`` = JSON list of ``{"name","tenant","role","key_sha256"}`` (plaintext
  ``"key"`` is accepted for development) for multi-tenant keys, or the legacy single ``NETDRIFT_API_KEY``
  (tenant ``default``, role ``admin``).

With nothing configured the API is open (development): every caller is ``default``/``admin``. Set
``NETDRIFT_REQUIRE_AUTH=1`` to make start-up fail instead.

Roles: ``viewer`` (read) < ``analyst`` (upload, analyze, baselines) < ``admin`` (delete).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Optional

import jwt
from fastapi import HTTPException, Request

ROLES = ("viewer", "analyst", "admin")


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str
    role: str

    def can(self, needed: str) -> bool:
        return ROLES.index(self.role) >= ROLES.index(needed)

    @property
    def key(self) -> str:
        return f"{self.tenant}:{self.subject}"


OPEN_PRINCIPAL = Principal("anonymous", "default", "admin")


# ---- configuration -----------------------------------------------------------------------------
@dataclass(frozen=True)
class AuthConfig:
    api_keys: tuple[tuple[str, Principal], ...]   # (sha256 hex of key, principal)
    jwt_key: Optional[str]
    jwt_alg: str
    jwt_issuer: Optional[str]
    jwt_audience: Optional[str]

    @property
    def enabled(self) -> bool:
        return bool(self.api_keys or self.jwt_key)


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


@lru_cache(maxsize=8)
def _load(single: str, multi: str, jwt_secret: str, jwt_pub: str, alg: str, iss: str, aud: str) -> AuthConfig:
    keys: list[tuple[str, Principal]] = []
    if single:
        keys.append((_sha(single), Principal("api-key", "default", "admin")))
    if multi:
        try:
            entries = json.loads(multi)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"NETDRIFT_API_KEYS is not valid JSON: {exc}") from exc
        for i, e in enumerate(entries):
            role = e.get("role", "viewer")
            if role not in ROLES:
                raise RuntimeError(f"NETDRIFT_API_KEYS[{i}]: role must be one of {ROLES}")
            digest = e.get("key_sha256") or (_sha(e["key"]) if e.get("key") else None)
            if not digest:
                raise RuntimeError(f"NETDRIFT_API_KEYS[{i}]: needs key_sha256 (or key)")
            keys.append((digest.lower(), Principal(e.get("name", f"key-{i}"), e.get("tenant", "default"), role)))
    key = jwt_secret or jwt_pub or None
    return AuthConfig(tuple(keys), key, alg or ("HS256" if jwt_secret else "RS256"), iss or None, aud or None)


def auth_config() -> AuthConfig:
    e = os.getenv
    return _load(e("NETDRIFT_API_KEY", ""), e("NETDRIFT_API_KEYS", ""), e("NETDRIFT_JWT_SECRET", ""),
                 e("NETDRIFT_JWT_PUBLIC_KEY", ""), e("NETDRIFT_JWT_ALGORITHM", ""), e("NETDRIFT_JWT_ISSUER", ""),
                 e("NETDRIFT_JWT_AUDIENCE", ""))


def issue_token(subject: str, tenant: str = "default", role: str = "viewer", ttl_seconds: int = 3600,
                secret: str | None = None) -> str:
    """Mint an HS256 token (for ops tooling/tests; normally your IdP issues these)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    secret = secret or os.environ["NETDRIFT_JWT_SECRET"]
    now = int(time.time())
    claims = {"sub": subject, "tenant": tenant, "role": role, "iat": now, "exp": now + ttl_seconds}
    iss, aud = os.getenv("NETDRIFT_JWT_ISSUER"), os.getenv("NETDRIFT_JWT_AUDIENCE")
    if iss:
        claims["iss"] = iss
    if aud:
        claims["aud"] = aud
    return jwt.encode(claims, secret, algorithm="HS256")


def _authenticate(request: Request, cfg: AuthConfig) -> Principal:
    authz = request.headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        if not cfg.jwt_key:
            raise HTTPException(401, "bearer tokens are not enabled", headers={"WWW-Authenticate": "Bearer"})
        try:
            claims = jwt.decode(
                authz[7:].strip(), cfg.jwt_key, algorithms=[cfg.jwt_alg], issuer=cfg.jwt_issuer, audience=cfg.jwt_audience,
                options={"require": ["exp", "sub"], "verify_iss": bool(cfg.jwt_issuer), "verify_aud": bool(cfg.jwt_audience)})
        except jwt.PyJWTError as exc:
            raise HTTPException(401, f"invalid token: {type(exc).__name__}", headers={"WWW-Authenticate": "Bearer"}) from exc
        role = claims.get("role", "viewer")
        tenant = str(claims.get("tenant", "default"))
        if role not in ROLES or not tenant or len(tenant) > 64:
            raise HTTPException(401, "token carries an invalid role/tenant claim")
        return Principal(str(claims["sub"]), tenant, role)
    presented = request.headers.get("x-api-key")
    if presented and cfg.api_keys:
        digest = _sha(presented)
        found = None
        for stored, principal in cfg.api_keys:  # compare against every entry: no early exit on timing
            if hmac.compare_digest(stored, digest):
                found = principal
        if found:
            return found
    raise HTTPException(401, "invalid or missing credentials (X-API-Key or Bearer token)",
                        headers={"WWW-Authenticate": "Bearer"})


# ---- rate limiting (token bucket, in-process) --------------------------------------------------
def parse_rate(spec: str) -> tuple[int, float]:
    """'120/minute' -> (120, 60.0)"""
    n, _, unit = spec.partition("/")
    secs = {"second": 1, "sec": 1, "s": 1, "minute": 60, "min": 60, "m": 60, "hour": 3600, "h": 3600}[unit.strip().lower()]
    return int(n), float(secs)


class RateLimiter:
    """Token bucket per key: `burst` tokens, refilled at burst/window per second. Thread-safe.
    In-process only; run one limiter in front (gateway/Redis) when scaling beyond one worker process."""

    def __init__(self, spec: str, clock: Callable[[], float] = time.monotonic) -> None:
        self.burst, self.window = parse_rate(spec)
        self.rate = self.burst / self.window
        self._clock = clock
        self._b: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def take(self, key: str) -> float:
        """Consume one token. Returns 0 if allowed, else seconds until a token is available."""
        now = self._clock()
        with self._lock:
            tokens, last = self._b.get(key, (float(self.burst), now))
            tokens = min(float(self.burst), tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self._b[key] = (tokens - 1.0, now)
                allowed = 0.0
            else:
                self._b[key] = (tokens, now)
                allowed = (1.0 - tokens) / self.rate
            if len(self._b) > 20000:  # evict idle buckets (full buckets carry no state)
                self._b = {k: v for k, v in self._b.items() if v[0] < self.burst}
            return allowed


@dataclass
class Limiters:
    normal: RateLimiter
    heavy: RateLimiter
    auth_fail: RateLimiter


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def guard(role: str = "viewer", heavy: bool = False):
    """FastAPI dependency factory: authenticate -> authorise -> rate limit. Returns the Principal."""

    def dependency(request: Request) -> Principal:
        limiters: Limiters = request.app.state.limiters
        cfg = auth_config()
        if cfg.enabled:
            try:
                principal = _authenticate(request, cfg)
            except HTTPException:
                wait = limiters.auth_fail.take(client_ip(request))
                if wait:
                    raise HTTPException(429, "too many failed authentication attempts",
                                        headers={"Retry-After": str(int(wait) + 1)}) from None
                raise
        else:
            principal = OPEN_PRINCIPAL
        if not principal.can(role):
            raise HTTPException(403, f"role '{principal.role}' may not perform this action (requires '{role}')")
        key = principal.key if cfg.enabled else client_ip(request)
        wait = (limiters.heavy if heavy else limiters.normal).take(key)
        if wait:
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(int(wait) + 1)})
        request.state.principal = principal
        return principal

    return dependency


# ---- request size enforcement ------------------------------------------------------------------
class BodyLimitMiddleware:
    """Pure-ASGI body cap: rejects on a declared Content-Length and also counts streamed bytes
    (chunked uploads without a length). Uploads get `upload_limit`, everything else `json_limit`."""

    def __init__(self, app, upload_limit: int, json_limit: int, upload_suffix: str = "/audit/upload") -> None:
        self.app, self.upload_limit, self.json_limit, self.upload_suffix = app, upload_limit, json_limit, upload_suffix

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS", "DELETE"):
            return await self.app(scope, receive, send)
        limit = self.upload_limit + 64 * 1024 if scope["path"].endswith(self.upload_suffix) else self.json_limit
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True
            if too_big:
                return await self._reject(send, limit)
        seen = 0
        started = rejected = False

        async def counted_receive():
            nonlocal seen, rejected
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit and not started and not rejected:
                    # Answer 413 ourselves: raising from here would be rewritten to 400 by the framework's
                    # body parsing. The app then sees a disconnect and its late response is swallowed.
                    rejected = True
                    await self._reject(send, limit)
                    return {"type": "http.disconnect"}
            return msg

        async def tracked_send(msg):
            nonlocal started
            if rejected:
                return
            if msg["type"] == "http.response.start":
                started = True
            await send(msg)

        try:
            await self.app(scope, counted_receive, tracked_send)
        except Exception:  # noqa: BLE001
            if not rejected:
                raise

    @staticmethod
    async def _reject(send, limit: int) -> None:
        body = json.dumps({"detail": f"request body exceeds {limit} bytes"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
