"""Tests for configuration secret redaction."""

from netdrift.sanitizer import sanitize_config


def test_sanitize_cisco_secrets():
    raw = (
        "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0\n"
        "username admin password 5 $1$XXXX$encryptedpass\n"
        "snmp-server community MyCompanyCommunityRO\n"
        "crypto isakmp key secretvpnkey123 address 192.0.2.1\n"
    )
    sanitized = sanitize_config(raw)

    assert "secretvpnkey123" not in sanitized
    assert "MyCompanyCommunityRO" not in sanitized
    assert "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized
    assert "[REDACTED_COMMUNITY]" in sanitized


def test_sanitize_sonicwall_secrets():
    raw = (
        'vpn policy "HQ-Branch"\n'
        '  shared-secret encrypted "8a9b0c1d2e3f"\n'
        'user local "admin" passphrase "SuperSecret123!"\n'
    )
    sanitized = sanitize_config(raw)

    assert "SuperSecret123!" not in sanitized
    assert "8a9b0c1d2e3f" not in sanitized
    assert "[REDACTED_KEY]" in sanitized
    assert "[REDACTED_SECRET]" in sanitized