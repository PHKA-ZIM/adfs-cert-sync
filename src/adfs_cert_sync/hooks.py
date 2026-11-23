from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess

from .models import SigningCertificate


class HookExecutionError(Exception):
    """Fehler bei der Ausführung eines Pre- oder Post-Hooks."""


def _build_hook_env(
    phase: str,
    cert_path: Path,
    cert: SigningCertificate | None = None,
    changed: bool | None = None,
    previous_fingerprint: str | None = None,
) -> dict[str, str]:
    """Baut die Umgebungsvariablen für Hook-Skripte zusammen."""
    env = dict(os.environ)
    env["ADFS_HOOK_PHASE"] = phase
    env["ADFS_CERT_PATH"] = str(cert_path)

    if changed is not None:
        env["ADFS_CERT_CHANGED"] = "1" if changed else "0"

    if previous_fingerprint:
        env["ADFS_PREV_CERT_SHA256"] = previous_fingerprint

    if cert is not None:
        env["ADFS_CERT_SHA256"] = cert.sha256_fingerprint
        env["ADFS_CERT_SUBJECT"] = cert.subject
        env["ADFS_CERT_ISSUER"] = cert.issuer
        env["ADFS_CERT_SERIAL"] = cert.serial_number
        env["ADFS_CERT_NOT_BEFORE"] = cert.not_valid_before.isoformat()
        env["ADFS_CERT_NOT_AFTER"] = cert.not_valid_after.isoformat()

    return env


def run_hook(
    command: str | None,
    phase: str,
    cert_path: Path,
    timeout_seconds: int = 60,
    cert: SigningCertificate | None = None,
    changed: bool | None = None,
    previous_fingerprint: str | None = None,
) -> None:
    """Führt einen Pre- oder Post-Hook aus, falls ein Kommando konfiguriert ist."""
    if not command or not command.strip():
        return

    args = shlex.split(command.strip())
    if not args:
        return

    env = _build_hook_env(
        phase=phase,
        cert_path=cert_path,
        cert=cert,
        changed=changed,
        previous_fingerprint=previous_fingerprint,
    )

    try:
        completed = subprocess.run(
            args,
            env=env,
            timeout=timeout_seconds,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HookExecutionError(
            f"{phase}-Hook konnte nicht gestartet werden (Datei/Befehl nicht gefunden): '{args[0]}'"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise HookExecutionError(
            f"{phase}-Hook lief nach {timeout_seconds}s in ein Timeout: '{command}'"
        ) from exc
    except OSError as exc:
        raise HookExecutionError(
            f"Systemfehler beim Ausführen des {phase}-Hooks '{command}': {exc}"
        ) from exc

    if completed.returncode != 0:
        stderr_snippet = (completed.stderr or "").strip()
        stdout_snippet = (completed.stdout or "").strip()
        details = stderr_snippet or stdout_snippet or "keine Ausgabe"
        raise HookExecutionError(
            f"{phase}-Hook '{command}' endete mit Exit-Code {completed.returncode}: {details}"
        )
