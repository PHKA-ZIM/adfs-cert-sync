from __future__ import annotations

from datetime import datetime, timezone
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .models import SigningCertificate


class CertificateValidationError(Exception):
    """Fehler bei der X.509-Prüfung oder Auswahl eines gültigen Zertifikats."""


def parse_der_certificate(der_bytes: bytes, source_index: int = 0) -> SigningCertificate:
    """Parst ein DER-kodiertes X.509-Zertifikat in ein SigningCertificate-Modell."""
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as exc:
        raise CertificateValidationError(
            f"Zertifikat an Index {source_index} konnte nicht als X.509 geladen werden: {exc}"
        ) from exc

    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    pem_text = pem_bytes.decode("ascii").strip() + "\n"

    # Kleingeschriebener SHA-256-Hex-Fingerabdruck (64 Zeichen)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex().lower()

    # Fallback-Hash falls nötig, hier direkt aus cryptography
    _ = hashlib.sha256(der_bytes).hexdigest()

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    return SigningCertificate(
        der_bytes=der_bytes,
        pem_text=pem_text,
        sha256_fingerprint=fingerprint,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=str(cert.serial_number),
        not_valid_before=not_before,
        not_valid_after=not_after,
        source_index=source_index,
    )


def parse_certificates(der_list: list[bytes]) -> list[SigningCertificate]:
    """Wandelt eine Liste von DER-Zertifikaten in SigningCertificate-Objekte um."""
    return [parse_der_certificate(der, idx) for idx, der in enumerate(der_list)]


def select_latest_valid_certificate(
    certificates: list[SigningCertificate],
    reference_time: datetime | None = None,
) -> SigningCertificate:
    """Wählt aus allen zum Zeitpunkt `reference_time` gültigen Zertifikaten das jüngste aus.

    'Jüngstes' bedeutet hier das Zertifikat mit dem spätesten Beginn der Gültigkeit
    (`not_valid_before`), damit neu ausgerollte Signing-Zertifikate sofort greifen,
    sobald ihr Gültigkeitsfenster begonnen hat.
    """
    now = reference_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    valid_certs = [cert for cert in certificates if cert.is_valid_at(now)]
    if not valid_certs:
        raise CertificateValidationError(
            f"Keines der {len(certificates)} Signing-Zertifikate ist zum Zeitpunkt "
            f"{now.isoformat()} gültig."
        )

    return max(valid_certs, key=lambda cert: (cert.not_valid_before, cert.source_index))
