from __future__ import annotations

from .config import CliOverrides, default_env_file_path, load_config, parse_dotenv_file
from .hooks import HookExecutionError, run_hook
from .metadata import (
    MetadataFetchError,
    MetadataParseError,
    extract_signing_certificates_der,
    fetch_metadata_xml,
)
from .models import AppConfig, HookConfig, SigningCertificate, SyncResult, SyncStatus
from .service import sync_adfs_certificate
from .storage import StorageError, read_current_certificate_fingerprint, write_current_certificate
from .validator import (
    CertificateValidationError,
    parse_certificates,
    parse_der_certificate,
    select_latest_valid_certificate,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AppConfig",
    "CertificateValidationError",
    "CliOverrides",
    "HookConfig",
    "HookExecutionError",
    "MetadataFetchError",
    "MetadataParseError",
    "SigningCertificate",
    "StorageError",
    "SyncResult",
    "SyncStatus",
    "default_env_file_path",
    "extract_signing_certificates_der",
    "fetch_metadata_xml",
    "load_config",
    "parse_certificates",
    "parse_der_certificate",
    "parse_dotenv_file",
    "read_current_certificate_fingerprint",
    "run_hook",
    "select_latest_valid_certificate",
    "sync_adfs_certificate",
    "write_current_certificate",
]
