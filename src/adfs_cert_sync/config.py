from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re

from .models import AppConfig, HookConfig

_ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$")


@dataclass(frozen=True)
class CliOverrides:
    """Optional übergebene Werte aus der Kommandozeile (None = nicht gesetzt)."""
    env_file: Path | None = None
    metadata_url: str | None = None
    cert_output_path: Path | None = None
    request_timeout_seconds: int | None = None
    log_level: str | None = None
    pre_hook: str | None = None
    post_hook: str | None = None
    post_hook_only_on_change: bool | None = None
    hook_timeout_seconds: int | None = None


def default_env_file_path() -> Path:
    """Liefert den Standardpfad zur .env-Datei im selben Verzeichnis (Projekt-/Skriptnähe)."""
    # src/adfs_cert_sync/config.py -> parents[2] ist das Projektverzeichnis;
    # liegt das Modul direkt in einem Ordner, ist parent das Verzeichnis daneben.
    module_dir = Path(__file__).resolve().parent
    candidate_in_package_dir = module_dir / ".env"
    if candidate_in_package_dir.exists():
        return candidate_in_package_dir

    candidate_in_repo_root = module_dir.parent.parent / ".env"
    return candidate_in_repo_root


def parse_dotenv_file(env_path: Path) -> dict[str, str]:
    """Liest einfache KEY=VALUE-Einträge aus einer .env-Datei."""
    values: dict[str, str] = {}
    if not env_path.exists():
        return values

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = _ENV_LINE_RE.match(raw_line)
        if not match:
            continue

        key, raw_val = match.group(1), match.group(2).strip()
        if len(raw_val) >= 2 and raw_val[0] == raw_val[-1] and raw_val[0] in ("'", '"'):
            quote = raw_val[0]
            inner = raw_val[1:-1]
            if quote == '"':
                inner = inner.replace('\\"', '"').replace("\\n", "\n")
            values[key] = inner
        else:
            # Inline-Kommentare bei unquotierten Werten entfernen
            if " #" in raw_val:
                raw_val = raw_val.split(" #", 1)[0].strip()
            values[key] = raw_val

    return values


def _resolve_str(
    cli_val: str | None,
    env_map: dict[str, str],
    dotenv_map: dict[str, str],
    key: str,
    default: str | None = None,
) -> str | None:
    if cli_val is not None and cli_val != "":
        return cli_val
    if key in env_map and env_map[key] != "":
        return env_map[key]
    if key in dotenv_map and dotenv_map[key] != "":
        return dotenv_map[key]
    return default


def _resolve_int(
    cli_val: int | None,
    env_map: dict[str, str],
    dotenv_map: dict[str, str],
    key: str,
    default: int,
) -> int:
    if cli_val is not None:
        return cli_val
    raw = _resolve_str(None, env_map, dotenv_map, key, None)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Ungültiger Ganzzahlwert für {key}: '{raw}'") from exc


def _resolve_bool(
    cli_val: bool | None,
    env_map: dict[str, str],
    dotenv_map: dict[str, str],
    key: str,
    default: bool,
) -> bool:
    if cli_val is not None:
        return cli_val
    raw = _resolve_str(None, env_map, dotenv_map, key, None)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in ("1", "true", "yes", "ja", "on"):
        return True
    if normalized in ("0", "false", "no", "nein", "off"):
        return False
    raise ValueError(f"Ungültiger Wahrheitswert für {key}: '{raw}'")


def load_config(overrides: CliOverrides | None = None) -> AppConfig:
    """Baut die finale AppConfig aus CLI-Overrides, System-Env und .env-Datei auf."""
    cli = overrides or CliOverrides()
    env_map = dict(os.environ)

    env_file = cli.env_file
    if env_file is None:
        env_from_sources = env_map.get("ADFS_ENV_FILE")
        env_file = Path(env_from_sources).expanduser() if env_from_sources else default_env_file_path()
    else:
        env_file = env_file.expanduser()

    dotenv_map = parse_dotenv_file(env_file)

    metadata_url = _resolve_str(
        cli.metadata_url, env_map, dotenv_map, "ADFS_METADATA_URL"
    )
    if not metadata_url:
        raise ValueError(
            "ADFS_METADATA_URL ist nicht gesetzt (weder per CLI, Umgebungsvariable noch .env)."
        )

    cert_out_raw = _resolve_str(
        str(cli.cert_output_path) if cli.cert_output_path else None,
        env_map,
        dotenv_map,
        "ADFS_CERT_OUTPUT_PATH",
        "./adfs_signing_cert.pem",
    )
    assert cert_out_raw is not None

    pre_hook = _resolve_str(cli.pre_hook, env_map, dotenv_map, "ADFS_PRE_HOOK")
    post_hook = _resolve_str(cli.post_hook, env_map, dotenv_map, "ADFS_POST_HOOK")
    post_hook_only_on_change = _resolve_bool(
        cli.post_hook_only_on_change,
        env_map,
        dotenv_map,
        "ADFS_POST_HOOK_ONLY_ON_CHANGE",
        True,
    )
    hook_timeout = _resolve_int(
        cli.hook_timeout_seconds,
        env_map,
        dotenv_map,
        "ADFS_HOOK_TIMEOUT_SECONDS",
        60,
    )
    req_timeout = _resolve_int(
        cli.request_timeout_seconds,
        env_map,
        dotenv_map,
        "ADFS_REQUEST_TIMEOUT_SECONDS",
        15,
    )
    log_level = (
        _resolve_str(cli.log_level, env_map, dotenv_map, "ADFS_LOG_LEVEL", "INFO") or "INFO"
    ).upper()

    return AppConfig(
        metadata_url=metadata_url,
        cert_output_path=Path(cert_out_raw).expanduser(),
        env_file=env_file,
        request_timeout_seconds=req_timeout,
        log_level=log_level,
        hooks=HookConfig(
            pre_hook=pre_hook,
            post_hook=post_hook,
            post_hook_only_on_change=post_hook_only_on_change,
            hook_timeout_seconds=hook_timeout,
        ),
    )
