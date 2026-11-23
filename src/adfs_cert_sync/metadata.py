from __future__ import annotations

import base64
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET


class MetadataFetchError(Exception):
    """Fehler beim Abrufen der FederationMetadata.xml."""


class MetadataParseError(Exception):
    """Fehler beim Parsen oder Extrahieren von Zertifikaten aus FederationMetadata.xml."""


_BASE64_CLEANUP_RE = re.compile(r"\s+")


def fetch_metadata_xml(url: str, timeout_seconds: int = 15, user_agent: str = "adfs-cert-sync/1.0") -> str:
    """Lädt die FederationMetadata.xml von der angegebenen URL."""
    request = Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "application/xml, text/xml, */*",
        },
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw_bytes = response.read()
    except HTTPError as exc:
        raise MetadataFetchError(
            f"HTTP-Fehler {exc.code} beim Abrufen der Metadaten von '{url}': {exc.reason}"
        ) from exc
    except URLError as exc:
        raise MetadataFetchError(
            f"Netzwerkfehler beim Abrufen der Metadaten von '{url}': {exc.reason}"
        ) from exc
    except TimeoutError as exc:
        raise MetadataFetchError(
            f"Timeout nach {timeout_seconds}s beim Abrufen der Metadaten von '{url}'"
        ) from exc
    except OSError as exc:
        raise MetadataFetchError(
            f"Systemfehler beim Abrufen der Metadaten von '{url}': {exc}"
        ) from exc

    if not raw_bytes:
        raise MetadataFetchError(f"Leere Antwort von Metadaten-URL '{url}' erhalten.")

    return raw_bytes.decode("utf-8", errors="replace")


def _local_name(tag: str) -> str:
    """Entfernt den XML-Namespace aus einem Tag-Namen, z. B. '{urn:...}KeyDescriptor' -> 'KeyDescriptor'."""
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _is_signing_key_descriptor(element: ET.Element) -> bool:
    """Prüft, ob ein KeyDescriptor für Signing genutzt wird.

    In SAML-Metadaten bedeutet ein fehlendes 'use'-Attribut oft 'both' (signing & encryption),
    während explizites use="encryption" ausgeschlossen werden muss.
    """
    use_attr = element.attrib.get("use")
    if use_attr is None:
        return True
    return use_attr.strip().lower() == "signing"


def extract_signing_certificates_der(xml_content: str) -> list[bytes]:
    """Extrahiert alle Signing-Zertifikate als DER-Bytes aus einer FederationMetadata.xml."""
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as exc:
        raise MetadataParseError(f"Ungültiges XML in FederationMetadata.xml: {exc}") from exc

    signing_certs_der: list[bytes] = []

    for elem in root.iter():
        if _local_name(elem.tag) != "KeyDescriptor":
            continue
        if not _is_signing_key_descriptor(elem):
            continue

        for sub in elem.iter():
            if _local_name(sub.tag) != "X509Certificate" or not sub.text:
                continue

            cleaned_b64 = _BASE64_CLEANUP_RE.sub("", sub.text.strip())
            if not cleaned_b64:
                continue

            try:
                der_bytes = base64.b64decode(cleaned_b64, validate=True)
            except Exception as exc:
                raise MetadataParseError(
                    f"Ungültiges Base64 in X509Certificate entdeckt: {exc}"
                ) from exc

            signing_certs_der.append(der_bytes)

    if not signing_certs_der:
        raise MetadataParseError(
            "Keine Signing-Zertifikate (<KeyDescriptor use=\"signing\"> / <X509Certificate>) gefunden."
        )

    return signing_certs_der
