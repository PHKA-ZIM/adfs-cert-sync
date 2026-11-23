from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys

from .config import CliOverrides, load_config
from .models import SyncStatus
from .service import sync_adfs_certificate


def _configure_logging(level_name: str) -> None:
    numeric_level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def build_parser() -> argparse.ArgumentParser:
    """Erstellt den Argument-Parser für das CLI."""
    parser = argparse.ArgumentParser(
        prog="adfs-cert-sync",
        description="Synchronisiert das aktuell gültige AD-FS-Signing-Zertifikat aus FederationMetadata.xml.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Pfad zu einer .env-Datei (Standard: .env im Projektverzeichnis).",
    )
    parser.add_argument(
        "--metadata-url",
        type=str,
        default=None,
        help="URL zur AD-FS FederationMetadata.xml.",
    )
    parser.add_argument(
        "--output",
        "--cert-output-path",
        dest="cert_output_path",
        type=Path,
        default=None,
        help="Zielpfad für die zwischengespeicherte Zertifikatsdatei (PEM).",
    )
    parser.add_argument(
        "--request-timeout",
        dest="request_timeout_seconds",
        type=int,
        default=None,
        help="HTTP-Timeout in Sekunden (Standard: 15).",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log-Level (DEBUG, INFO, WARNING, ERROR).",
    )
    parser.add_argument(
        "--pre-hook",
        type=str,
        default=None,
        help="Kommando/Skript, das vor dem Abruf ausgeführt wird.",
    )
    parser.add_argument(
        "--post-hook",
        type=str,
        default=None,
        help="Kommando/Skript, das nach erfolgreichem Lauf ausgeführt wird.",
    )
    parser.add_argument(
        "--hook-timeout",
        dest="hook_timeout_seconds",
        type=int,
        default=None,
        help="Timeout für Pre-/Post-Hooks in Sekunden (Standard: 60).",
    )

    only_on_change_group = parser.add_mutually_exclusive_group()
    only_on_change_group.add_argument(
        "--post-hook-only-on-change",
        dest="post_hook_only_on_change",
        action="store_true",
        default=None,
        help="Post-Hook nur bei geänderten Zertifikaten ausführen.",
    )
    only_on_change_group.add_argument(
        "--post-hook-always",
        dest="post_hook_only_on_change",
        action="store_false",
        default=None,
        help="Post-Hook auch dann ausführen, wenn das Zertifikat unverändert ist.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Haupteinstiegspunkt für CLI und Cronjobs."""
    parser = build_parser()
    args = parser.parse_args(argv)

    overrides = CliOverrides(
        env_file=args.env_file,
        metadata_url=args.metadata_url,
        cert_output_path=args.cert_output_path,
        request_timeout_seconds=args.request_timeout_seconds,
        log_level=args.log_level,
        pre_hook=args.pre_hook,
        post_hook=args.post_hook,
        post_hook_only_on_change=args.post_hook_only_on_change,
        hook_timeout_seconds=args.hook_timeout_seconds,
    )

    try:
        config = load_config(overrides=overrides)
    except ValueError as exc:
        print(f"Konfigurationsfehler: {exc}", file=sys.stderr)
        return 2

    _configure_logging(config.log_level)
    result = sync_adfs_certificate(config=config)

    if result.status == SyncStatus.FAILED:
        print(f"Fehler: {result.message}", file=sys.stderr)
        return 1

    print(result.message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
