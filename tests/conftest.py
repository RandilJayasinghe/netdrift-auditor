import os
import tempfile
from pathlib import Path

import pytest

from netdrift.parsers import parse_config
from netdrift.schemas import AuditProfile

# The module-level FastAPI `app` is created at import time: point it at a throw-away database.
os.environ.setdefault("NETDRIFT_DATABASE_URL", f"sqlite:///{tempfile.mkdtemp(prefix='netdrift-test-')}/default.db")

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def sonic_text() -> str:
    return (FIX / "bank_hq_sonicwall.conf").read_text()


@pytest.fixture(scope="session")
def cfg(sonic_text):
    return parse_config(sonic_text)


@pytest.fixture(scope="session")
def profile() -> AuditProfile:
    return AuditProfile.model_validate_json((FIX / "profile.json").read_text())
