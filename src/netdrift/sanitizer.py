"""Firewall configuration sanitization and secret redaction.

Credentials are stripped *before* parsing, persisting or logging. Three layers:

1. `sanitize_config`        regex redaction of vendor secret syntax (CLI text and JSON key/value forms).
2. `sanitize_for_storage`   returns a `SanitizedConfig`, the only type the persistence layer accepts.
3. `verify_sanitized`       re-checks text right before it is written: it must be a fixed point of
                            `sanitize_config` and contain no high-confidence secret material
                            (unredacted FortiOS `ENC` blobs, PEM private keys, crypt hashes).
`install_log_redaction` applies layer 1 to every `netdrift.*` log record so a stray message can not leak a secret.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass

from .errors import SecretLeakError

_I = re.IGNORECASE

# Patterns matching vendor secret declarations (SonicWall, Cisco ASA, FortiOS, JSON exports, ...).
# Order matters: the specific `... ENC <blob>` forms must run before the generic `password <x>` form.
SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # FortiOS encrypted/plain secrets:  set password ENC <blob>  /  set psksecret ENC <blob>
    (re.compile(r"(\b(?:password|passwd|psksecret|secret|auth-password|priv-password|private-key|passphrase|key)\s+)ENC\s+\S+", _I),
     r"\1[REDACTED_SECRET]"),
    (re.compile(r"(\b(?:psksecret|passwd|auth-password|priv-password|private-key)\s+)(?!\[REDACTED)(?!ENC\b)(\S+)", _I),
     r"\1[REDACTED_SECRET]"),
    # PEM blocks (private keys / certificates with keys)
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]"),
    # JSON exports (FMC, iptables dumps, ...):  "password": "x"
    (re.compile(r'("(?:password|passwd|secret|psk|pre_?shared_?key|private_?key|api_?key|token|community|auth_?key|'
                r'shared_?secret|passphrase)"\s*:\s*)"[^"]*"', _I), r'\1"[REDACTED_SECRET]"'),
    # Cisco ASA / IOS passwords, keys, and hashes
    (re.compile(r'(password\s+)(?:pbkdf2\s+)?(?:\d+\s+)?([^\s"]+)', _I), r"\1[REDACTED_SECRET]"),
    (re.compile(r"((?:pre-shared-key|key-string|authentication-key|(?:crypto\s+(?:isakmp|ikev2)\s+key))\s+)(?:hex\s+)?(\S+)", _I),
     r"\1[REDACTED_KEY]"),
    (re.compile(r"^(\s*(?:tacacs-server\s+|radius-server\s+)?key\s+)(?:\d+\s+)?(?!\[REDACTED)(\S+)", _I | re.M), r"\1[REDACTED_KEY]"),
    (re.compile(r"(snmp-server\s+community\s+)(\S+)", _I), r"\1[REDACTED_COMMUNITY]"),
    (re.compile(r"(enable\s+secret(?:\s+\d+)?\s+)(\S+)", _I), r"\1[REDACTED_SECRET]"),
    # SonicWall credentials and PSKs
    (re.compile(r"(shared-secret\s+)(?:encrypted\s+)?(\S+)", _I), r"\1[REDACTED_KEY]"),
    (re.compile(r"(passphrase\s+)(\S+)", _I), r"\1[REDACTED_SECRET]"),
    # Generic token / hex hash matchers
    (re.compile(r"(md5|sha256|hash)\s+([a-f0-9]{32,64})", _I), r"\1 [REDACTED_HASH]"),
]

# High-confidence residue detectors used by `verify_sanitized` (must not false-positive on prose).
_RESIDUE: list[tuple[str, re.Pattern[str]]] = [
    ("FortiOS ENC secret", re.compile(r"\bENC\s+(?!\[REDACTED)[A-Za-z0-9+/=]{16,}")),
    ("PEM private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("crypt(3) password hash", re.compile(r"\$(?:1|2[aby]?|5|6|y)\$[./A-Za-z0-9$]{8,}")),
    # also matches the backslash-escaped form a JSON document takes when embedded in a string field
    ("JSON secret value", re.compile(r'\\?"(?:password|passwd|psk|pre_?shared_?key|private_?key|api_?key|shared_?secret)\\?"\s*:\s*\\?"(?!\[REDACTED)[^"\\]+', _I)),
]


def sanitize_config(text: str) -> str:
    """Redact passwords, PSKs, and secret hashes from raw configuration text.

    Ensures that credentials are stripped before parsing, graph generation,
    or logging to prevent accidental credential leakage.
    """
    sanitized = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


@dataclass(frozen=True)
class SanitizedConfig:
    """Config text that has been through `sanitize_config`. The persistence layer only accepts this."""
    text: str
    sha256: str       # of the *sanitized* text (stable identity without retaining the original)
    redactions: int   # how many secret tokens were removed


def sanitize_for_storage(raw: str) -> SanitizedConfig:
    clean = sanitize_config(raw)
    redactions = len(re.findall(r"\[REDACTED_[A-Z_]+\]", clean)) - len(re.findall(r"\[REDACTED_[A-Z_]+\]", raw))
    return SanitizedConfig(clean, hashlib.sha256(clean.encode()).hexdigest(), max(redactions, 0))


def find_residual_secrets(text: str) -> list[str]:
    return [label for label, rx in _RESIDUE if rx.search(text)]


def verify_sanitized(text: str) -> None:
    """Raise `SecretLeakError` unless `text` is already clean. Called immediately before DB writes."""
    problems = find_residual_secrets(text)
    if not problems and sanitize_config(text) != text:
        problems = ["unredacted credential syntax"]
    if problems:
        raise SecretLeakError("refusing to persist unsanitized configuration data: " + ", ".join(problems))


class RedactingFilter(logging.Filter):
    """Scrub secrets from log records (message and args are rendered, redacted, then frozen)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # malformed format string; never let logging raise
            return True
        clean = sanitize_config(msg)
        if clean != msg:
            record.msg, record.args = clean, None
        return True


def install_log_redaction(prefix: str = "netdrift") -> None:
    """Redact every record emitted by loggers named `prefix` / `prefix.*`.

    A logger-level Filter is *not* consulted for records propagating up from child loggers
    (`netdrift.jobs`), so redaction is installed in the record factory, before any handler sees it."""
    current = logging.getLogRecordFactory()
    if getattr(current, "_netdrift_redacting", False):
        return
    redactor = RedactingFilter()

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003
        record = current(*args, **kwargs)
        if record.name == prefix or record.name.startswith(prefix + "."):
            redactor.filter(record)
        return record

    factory._netdrift_redacting = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(factory)
