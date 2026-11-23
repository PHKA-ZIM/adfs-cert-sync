from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from adfs_cert_sync.storage import (
    read_current_certificate_fingerprint,
    write_current_certificate,
)
from adfs_cert_sync.validator import parse_der_certificate
from .test_validator import _make_self_signed_der


def test_write_and_read_fingerprint(tmp_path: Path) -> None:
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    der = _make_self_signed_der(
        "ADFS-Storage-Test",
        now - timedelta(days=1),
        now + timedelta(days=30),
    )
    parsed = parse_der_certificate(der)
    target_file = tmp_path / "certs" / "adfs_signing_cert.pem"

    assert read_current_certificate_fingerprint(target_file) is None

    write_current_certificate(parsed, target_file)

    assert target_file.exists()
    content = target_file.read_text(encoding="ascii")
    assert content.startswith("-----BEGIN CERTIFICATE-----")
    assert read_current_certificate_fingerprint(target_file) == parsed.sha256_fingerprint
