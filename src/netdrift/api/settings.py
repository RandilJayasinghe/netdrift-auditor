"""Runtime settings read from the environment (12-factor). Auth settings are read per request in
`security.py` so credentials can be rotated without a restart; everything here is fixed at start-up."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    database_url: str = "sqlite:///netdrift.db"
    max_upload_bytes: int = 20 * 1024 * 1024    # config file uploads
    max_json_bytes: int = 2 * 1024 * 1024       # every other request body
    rate_limit: str = "120/minute"              # per principal (or client IP when unauthenticated)
    rate_limit_heavy: str = "20/minute"         # upload / analyze / job submission
    auth_fail_limit: str = "10/minute"          # failed authentications per client IP (brute-force guard)
    async_workers: int = 2                      # 0 = run jobs inline (synchronous fallback)
    require_auth: bool = field(default_factory=lambda: False)

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.getenv
        return cls(
            database_url=e("NETDRIFT_DATABASE_URL", cls.database_url),
            max_upload_bytes=int(e("NETDRIFT_MAX_UPLOAD_BYTES", cls.max_upload_bytes)),
            max_json_bytes=int(e("NETDRIFT_MAX_JSON_BYTES", cls.max_json_bytes)),
            rate_limit=e("NETDRIFT_RATE_LIMIT", cls.rate_limit),
            rate_limit_heavy=e("NETDRIFT_RATE_LIMIT_HEAVY", cls.rate_limit_heavy),
            auth_fail_limit=e("NETDRIFT_AUTH_FAIL_LIMIT", cls.auth_fail_limit),
            async_workers=int(e("NETDRIFT_ASYNC_WORKERS", cls.async_workers)),
            require_auth=_flag("NETDRIFT_REQUIRE_AUTH"),
        )
