from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from adfs_cert_sync import metadata as metadata_module
from adfs_cert_sync.models import AppConfig, HookConfig, SyncStatus
from adfs_cert_sync.service import sync_adfs_certificate
from .test_validator import _make_self_signed_der


def _xml_with_certs(der_list: list[bytes]) -> str:
    descriptors = []
    for der in der_list:
        b64 = base64.b64encode(der).decode("ascii")
        descriptors.append(
            f"""
            <KeyDescriptor use="signing">
              <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                  <X509Certificate>{b64}</X509Certificate>
                </X509Data>
              </KeyInfo>
            </KeyDescriptor>
            """
        )
    return f"""<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="http://fs.beispiel.de/adfs/services/trust">
  <RoleDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    {"".join(descriptors)}
  </RoleDescriptor>
</EntityDescriptor>
"""


def test_sync_updates_then_unchanged_and_runs_post_hook_on_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
    shared_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    cert1_der = _make_self_signed_der(
        "ADFS-Cert-1",
        now - timedelta(days=10),
        now + timedelta(days=20),
        key=shared_key,
    )
    cert2_der = _make_self_signed_der(
        "ADFS-Cert-2",
        now - timedelta(days=1),
        now + timedelta(days=50),
        key=shared_key,
    )

    hook_log = tmp_path / "hook_calls.log"
    post_hook_script = tmp_path / "post_hook.sh"
    post_hook_script.write_text(
        f'#!/usr/bin/env bash\necho "$ADFS_HOOK_PHASE:$ADFS_CERT_CHANGED:$ADFS_CERT_SHA256" >> "{hook_log}"\n',
        encoding="utf-8",
    )
    post_hook_script.chmod(0o755)

    cert_out = tmp_path / "adfs_signing_cert.pem"
    config = AppConfig(
        metadata_url="https://example.invalid/FederationMetadata.xml",
        cert_output_path=cert_out,
        env_file=None,
        hooks=HookConfig(
            post_hook=str(post_hook_script),
            post_hook_only_on_change=True,
        ),
    )

    # Lauf 1: Erstes Zertifikat -> UPDATED, Post-Hook läuft
    monkeypatch.setattr(
        metadata_module,
        "fetch_metadata_xml",
        lambda url, timeout_seconds=15: _xml_with_certs([cert1_der]),
    )
    res1 = sync_adfs_certificate(config, reference_time=now)
    assert res1.status == SyncStatus.UPDATED
    assert res1.changed is True
    assert cert_out.exists()

    # Lauf 2: Gleiches Zertifikat -> UNCHANGED, Post-Hook läuft wegen only_on_change=True NICHT erneut
    res2 = sync_adfs_certificate(config, reference_time=now)
    assert res2.status == SyncStatus.UNCHANGED
    assert res2.changed is False
    assert len(hook_log.read_text(encoding="utf-8").splitlines()) == 1

    # Lauf 3: Neueres gültiges Zertifikat taucht auf -> UPDATED, Post-Hook läuft erneut
    monkeypatch.setattr(
        metadata_module,
        "fetch_metadata_xml",
        lambda url, timeout_seconds=15: _xml_with_certs([cert1_der, cert2_der]),
    )
    res3 = sync_adfs_certificate(config, reference_time=now)
    assert res3.status == SyncStatus.UPDATED
    assert res3.changed is True
    assert len(hook_log.read_text(encoding="utf-8").splitlines()) == 2


def test_failing_pre_hook_aborts_sync(tmp_path: Path) -> None:
    cert_out = tmp_path / "adfs_signing_cert.pem"
    config = AppConfig(
        metadata_url="https://example.invalid/FederationMetadata.xml",
        cert_output_path=cert_out,
        env_file=None,
        hooks=HookConfig(pre_hook="false"),
    )

    result = sync_adfs_certificate(config)
    assert result.status == SyncStatus.FAILED
    assert result.changed is False
    assert not cert_out.exists()
