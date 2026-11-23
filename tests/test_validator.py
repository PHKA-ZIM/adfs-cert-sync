from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from adfs_cert_sync.validator import (
    CertificateValidationError,
    parse_certificates,
    select_latest_valid_certificate,
)


def _make_self_signed_der(
    cn: str,
    not_before: datetime,
    not_after: datetime,
    key: rsa.RSAPrivateKey | None = None,
) -> bytes:
    private_key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_selects_newest_valid_certificate_and_skips_expired_or_future() -> None:
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    shared_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    expired_der = _make_self_signed_der(
        "ADFS-Expired",
        now - timedelta(days=90),
        now - timedelta(days=1),
        key=shared_key,
    )
    older_valid_der = _make_self_signed_der(
        "ADFS-Old-Valid",
        now - timedelta(days=30),
        now + timedelta(days=30),
        key=shared_key,
    )
    newer_valid_der = _make_self_signed_der(
        "ADFS-New-Valid",
        now - timedelta(days=2),
        now + timedelta(days=88),
        key=shared_key,
    )
    future_der = _make_self_signed_der(
        "ADFS-Future",
        now + timedelta(days=10),
        now + timedelta(days=100),
        key=shared_key,
    )

    certs = parse_certificates([expired_der, older_valid_der, newer_valid_der, future_der])
    selected = select_latest_valid_certificate(certs, reference_time=now)

    assert "CN=ADFS-New-Valid" in selected.subject


def test_raises_when_no_certificate_is_valid() -> None:
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    shared_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    expired_der = _make_self_signed_der(
        "ADFS-Expired",
        now - timedelta(days=20),
        now - timedelta(days=5),
        key=shared_key,
    )
    certs = parse_certificates([expired_der])

    with pytest.raises(CertificateValidationError, match="Keines der 1 Signing-Zertifikate"):
        select_latest_valid_certificate(certs, reference_time=now)
