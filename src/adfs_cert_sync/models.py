from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from enum import Enum


class SyncStatus(str, Enum):
    """Mögliche Ergebnisse eines Synchronisationslaufs."""
    UNCHANGED = "unchanged"
    UPDATED = "updated"
    FAILED = "failed"


@dataclass(frozen=True)
class SigningCertificate:
    """Repräsentiert ein aus FederationMetadata.xml extrahiertes Signing-Zertifikat."""
    der_bytes: bytes
    pem_text: str
    sha256_fingerprint: str
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    source_index: int

    def is_valid_at(self, reference_time: datetime) -> bool:
        """Prüft, ob das Zertifikat zum angegebenen UTC-Zeitpunkt gültig ist."""
        return self.not_valid_before <= reference_time <= self.not_valid_after


@dataclass(frozen=True)
class HookConfig:
    """Konfiguration für Pre- und Post-Hooks."""
    pre_hook: str | None = None
    post_hook: str | None = None
    post_hook_only_on_change: bool = True
    hook_timeout_seconds: int = 60


@dataclass(frozen=True)
class AppConfig:
    """Gesamtkonfiguration für den AD-FS-Zertifikatsabgleich."""
    metadata_url: str
    cert_output_path: Path
    env_file: Path | None
    request_timeout_seconds: int = 15
    log_level: str = "INFO"
    hooks: HookConfig = HookConfig()


@dataclass(frozen=True)
class SyncResult:
    """Ergebnis eines Durchlaufs für Logging, Exit-Codes und Hooks."""
    status: SyncStatus
    changed: bool
    message: str
    active_certificate: SigningCertificate | None = None
    previous_fingerprint: str | None = None
