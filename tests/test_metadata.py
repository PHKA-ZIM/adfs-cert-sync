from __future__ import annotations

import base64
import pytest

from adfs_cert_sync.metadata import MetadataParseError, extract_signing_certificates_der


def _wrap_metadata(key_descriptors_xml: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="http://fs.beispiel.de/adfs/services/trust">
  <RoleDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    {key_descriptors_xml}
  </RoleDescriptor>
</EntityDescriptor>
"""


def test_extracts_only_signing_certificates_and_ignores_encryption() -> None:
    sign_der = b"fake-signing-cert-der"
    enc_der = b"fake-encryption-cert-der"

    sign_b64 = base64.b64encode(sign_der).decode("ascii")
    # Zeilenumbrüche im Base64 sind in XML-Zertifikaten üblich und müssen sauber bereinigt werden
    sign_b64_multiline = "\n".join([sign_b64[:12], sign_b64[12:]])
    enc_b64 = base64.b64encode(enc_der).decode("ascii")

    xml = _wrap_metadata(
        f"""
        <KeyDescriptor use="signing">
          <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
              <X509Certificate>{sign_b64_multiline}</X509Certificate>
            </X509Data>
          </KeyInfo>
        </KeyDescriptor>
        <KeyDescriptor use="encryption">
          <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
              <X509Certificate>{enc_b64}</X509Certificate>
            </X509Data>
          </KeyInfo>
        </KeyDescriptor>
        """
    )

    result = extract_signing_certificates_der(xml)
    assert result == [sign_der]


def test_raises_on_invalid_xml() -> None:
    with pytest.raises(MetadataParseError, match="Ungültiges XML"):
        extract_signing_certificates_der("<EntityDescriptor><broken>")


def test_raises_when_no_signing_certificate_present() -> None:
    enc_b64 = base64.b64encode(b"only-enc").decode("ascii")
    xml = _wrap_metadata(
        f"""
        <KeyDescriptor use="encryption">
          <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
            <X509Data>
              <X509Certificate>{enc_b64}</X509Certificate>
            </X509Data>
          </KeyInfo>
        </KeyDescriptor>
        """
    )

    with pytest.raises(MetadataParseError, match="Keine Signing-Zertifikate"):
        extract_signing_certificates_der(xml)
