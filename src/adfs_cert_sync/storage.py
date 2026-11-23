from __future__ import annotations

import os
from pathlib import Path
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .models import SigningCertificate


class StorageError(Exception):
    """Fehler beim Lesen oder Schreiben der Zertifikatsdatei."""


def read_current_certificate_fingerprint(cert_path: Path) -> str | None:
    """Liest den SHA-256-Fingerabdruck des aktuell gespeicherten Zertifikats.

    Gibt None zurück, wenn die Datei noch nicht existiert oder kein gültiges PEM/DER enthält.
    """
    if not cert_path.exists() or not cert_path.is_file():
        return None

    try:
        raw = cert_path.read_bytes()
        if not raw.strip():
            return None

        if b"-----BEGIN CERTIFICATE-----" in raw:
            cert = x509.load_pem_x509_certificate(raw)
        else:
            cert = x509.load_der_x509_certificate(raw)

        return cert.fingerprint(hashes.SHA256()).hex().lower()
    except Exception:
        # Falls die Datei korrupt oder manuell geändert wurde, als nicht identisch behandeln
        return None


def write_current_certificate(cert: SigningCertificate, cert_path: Path) -> None:
    """Schreibt das PEM-Zertifikat atomar an `cert_path` (ohne Historie)."""
    tmp_path: Path | None = None
    try:
        cert_path.parent.mkdir(parents=True, exist_ok=True)

        # Temporäre Datei im selben Zielverzeichnis anlegen, damit os.replace()
        # immer auf demselben Filesystem stattfindet (garantiert atomar).
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{cert_path.name}.",
            suffix=".tmp",
            dir=str(cert_path.parent),
        )
        tmp_path = Path(tmp_name)

        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(cert.pem_text)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            # Falls fdopen fehlschlägt, fd sauber schließen
            try:
                os.close(fd)
            except OSError:
                pass
            raise

        os.replace(tmp_path, cert_path)
    except Exception as exc:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise StorageError(
            f"Konnte Zertifikat nicht nach '{cert_path}' schreiben: {exc}"
        ) from exc
