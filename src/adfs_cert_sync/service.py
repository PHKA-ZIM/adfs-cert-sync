from __future__ import annotations

from datetime import datetime, timezone
import logging

from .hooks import HookExecutionError, run_hook
from .metadata import (
    MetadataFetchError,
    MetadataParseError,
    extract_signing_certificates_der,
    fetch_metadata_xml,
)
from .models import AppConfig, SyncResult, SyncStatus
from .storage import (
    StorageError,
    read_current_certificate_fingerprint,
    write_current_certificate,
)
from .validator import (
    CertificateValidationError,
    parse_certificates,
    select_latest_valid_certificate,
)

logger = logging.getLogger(__name__)


def sync_adfs_certificate(
    config: AppConfig,
    reference_time: datetime | None = None,
) -> SyncResult:
    """Führt den kompletten Synchronisationslauf für das AD-FS-Signing-Zertifikat aus."""
    now = reference_time or datetime.now(timezone.utc)
    previous_fingerprint = read_current_certificate_fingerprint(config.cert_output_path)

    # 1. Pre-Hook ausführen
    if config.hooks.pre_hook:
        logger.debug("Führe Pre-Hook aus: %s", config.hooks.pre_hook)
        try:
            run_hook(
                command=config.hooks.pre_hook,
                phase="pre",
                cert_path=config.cert_output_path,
                timeout_seconds=config.hooks.hook_timeout_seconds,
                changed=False,
                previous_fingerprint=previous_fingerprint,
            )
        except HookExecutionError as exc:
            logger.error("Pre-Hook fehlgeschlagen: %s", exc)
            return SyncResult(
                status=SyncStatus.FAILED,
                changed=False,
                message=str(exc),
                previous_fingerprint=previous_fingerprint,
            )

    # 2. Metadaten abrufen & Signing-Zertifikate extrahieren
    try:
        logger.info("Lade AD-FS-Metadaten von %s", config.metadata_url)
        xml_content = fetch_metadata_xml(
            url=config.metadata_url,
            timeout_seconds=config.request_timeout_seconds,
        )
        der_list = extract_signing_certificates_der(xml_content)
        parsed_certs = parse_certificates(der_list)
        selected_cert = select_latest_valid_certificate(parsed_certs, reference_time=now)
    except (MetadataFetchError, MetadataParseError, CertificateValidationError) as exc:
        logger.error("Metadaten- oder Zertifikatsprüfung fehlgeschlagen: %s", exc)
        return SyncResult(
            status=SyncStatus.FAILED,
            changed=False,
            message=str(exc),
            previous_fingerprint=previous_fingerprint,
        )

    logger.info(
        "Aktives gültiges Signing-Zertifikat gewählt: SHA-256=%s, gültig bis %s",
        selected_cert.sha256_fingerprint,
        selected_cert.not_valid_after.isoformat(),
    )

    # 3. Prüfen, ob eine Änderung gegenüber dem zwischengespeicherten Zertifikat vorliegt
    changed = previous_fingerprint != selected_cert.sha256_fingerprint

    if changed:
        try:
            write_current_certificate(selected_cert, config.cert_output_path)
            logger.info("Neues Zertifikat geschrieben nach: %s", config.cert_output_path)
        except StorageError as exc:
            logger.error("Fehler beim Speichern des Zertifikats: %s", exc)
            return SyncResult(
                status=SyncStatus.FAILED,
                changed=False,
                message=str(exc),
                active_certificate=selected_cert,
                previous_fingerprint=previous_fingerprint,
            )
    else:
        logger.info(
            "Zertifikat unverändert (SHA-256=%s). Kein Schreiben erforderlich.",
            selected_cert.sha256_fingerprint,
        )

    # 4. Post-Hook ausführen
    should_run_post_hook = bool(config.hooks.post_hook) and (
        changed or not config.hooks.post_hook_only_on_change
    )

    if should_run_post_hook:
        logger.debug("Führe Post-Hook aus: %s", config.hooks.post_hook)
        try:
            run_hook(
                command=config.hooks.post_hook,
                phase="post",
                cert_path=config.cert_output_path,
                timeout_seconds=config.hooks.hook_timeout_seconds,
                cert=selected_cert,
                changed=changed,
                previous_fingerprint=previous_fingerprint,
            )
        except HookExecutionError as exc:
            logger.error("Post-Hook fehlgeschlagen: %s", exc)
            return SyncResult(
                status=SyncStatus.FAILED,
                changed=changed,
                message=f"Zertifikat aktualisiert, aber Post-Hook fehlgeschlagen: {exc}",
                active_certificate=selected_cert,
                previous_fingerprint=previous_fingerprint,
            )

    if changed:
        return SyncResult(
            status=SyncStatus.UPDATED,
            changed=True,
            message=f"Zertifikat aktualisiert ({selected_cert.sha256_fingerprint}).",
            active_certificate=selected_cert,
            previous_fingerprint=previous_fingerprint,
        )

    return SyncResult(
        status=SyncStatus.UNCHANGED,
        changed=False,
        message=f"Zertifikat bereits aktuell ({selected_cert.sha256_fingerprint}).",
        active_certificate=selected_cert,
        previous_fingerprint=previous_fingerprint,
    )
