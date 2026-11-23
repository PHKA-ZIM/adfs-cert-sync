# adfs-cert-sync

Kleine Python-Library und CLI zum automatischen Abrufen, Prüfen und Zwischenspeichern des **aktuell gültigen Signing-Zertifikats** aus einer öffentlichen AD-FS `FederationMetadata.xml`.

Das Tool speichert jeweils nur das **aktuelle Zertifikat** im PEM-Format (ohne Historie) und bietet **Pre- und Post-Hooks**, damit Zielsysteme (z. B. `.env`-Dateien, MySQL-Felder oder Cache-/Service-Reloads wie TYPO3) entkoppelt angebunden werden können.

---

## Funktionsweise im Überblick

1. **Pre-Hook (optional):** Wird vor dem Metadaten-Abruf ausgeführt (z. B. für Vorbedingungen oder Checks). Schlägt er fehl, bricht der Lauf ab.
2. **Metadaten abrufen & parsen:** Lädt die `FederationMetadata.xml` und extrahiert Zertifikate aus `KeyDescriptor`-Elementen für Signing.
3. **Gültigkeit prüfen & jüngstes gültiges Zertifikat wählen:** Prüft den Gültigkeitszeitraum (`not_valid_before` / `not_valid_after` in UTC) und wählt das jüngste gültige Zertifikat (sobald ein neues gültiges Zertifikat in den Metadaten erscheint, wird es bevorzugt).
4. **Atomarer Cache-Write:** Vergleicht den SHA-256-Fingerabdruck mit der bereits gespeicherten Datei. Nur bei einer Änderung wird die Zieldatei über eine temporäre Datei und `os.replace()` atomar aktualisiert.
5. **Post-Hook (optional):** Wird nach erfolgreichem Lauf ausgeführt (standardmäßig nur bei geändertem Zertifikat) und erhält Zertifikatsdaten über Umgebungsvariablen.

---

## Installation

Im Projektverzeichnis (`adfs-cert-sync/`):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Für Entwicklung und Tests (`pytest`):

```bash
pip install -e ".[dev]"
pytest
```

---

## Konfiguration & Vorrangregeln

Einstellungen werden in dieser Reihenfolge aufgelöst (**höchste Priorität zuerst**):

1. **CLI-Parameter** (z. B. `--metadata-url`, `--output`, `--post-hook`)
2. **Prozess-Umgebungsvariablen** (z. B. aus Cron oder Systemd)
3. **`.env`-Datei** (Standard: `.env` im Projektverzeichnis neben `.env.example`; überschreibbar mit `--env-file`)

Kopiere `.env.example` nach `.env` und passe die Werte an:

```bash
cp .env.example .env
```

Verfügbare Variablen:

| Variable | Pflicht | Standard | Beschreibung |
| :--- | :---: | :--- | :--- |
| `ADFS_METADATA_URL` | Ja | – | Öffentliche URL zur `FederationMetadata.xml` |
| `ADFS_CERT_OUTPUT_PATH` | Nein | `./adfs_signing_cert.pem` | Zielpfad für das aktuelle PEM-Zertifikat |
| `ADFS_REQUEST_TIMEOUT_SECONDS` | Nein | `15` | Timeout für den HTTP-Abruf in Sekunden |
| `ADFS_LOG_LEVEL` | Nein | `INFO` | `DEBUG`, `INFO`, `WARNING` oder `ERROR` |
| `ADFS_PRE_HOOK` | Nein | – | Kommando/Skript vor dem Metadaten-Abruf |
| `ADFS_POST_HOOK` | Nein | – | Kommando/Skript nach erfolgreichem Lauf |
| `ADFS_POST_HOOK_ONLY_ON_CHANGE` | Nein | `true` | `true`: Post-Hook nur bei Änderung; `false`: immer |
| `ADFS_HOOK_TIMEOUT_SECONDS` | Nein | `60` | Timeout für Hooks in Sekunden |

---

## CLI-Beispiele

### 1. Betrieb über `.env` im Projektverzeichnis

```bash
/pfad/zu/adfs-cert-sync/.venv/bin/adfs-cert-sync
```

### 2. Betrieb mit eigener `.env`-Datei und CLI-Overrides

```bash
adfs-cert-sync \
  --env-file /etc/adfs-cert-sync/app1.env \
  --output /var/lib/adfs-cert-sync/signing.pem \
  --log-level INFO
```

### 3. Betrieb komplett ohne `.env` nur über Parameter

```bash
adfs-cert-sync \
  --metadata-url "https://fs.beispiel.de/FederationMetadata/2007-06/FederationMetadata.xml" \
  --output "/opt/app/certs/adfs-signing.pem" \
  --pre-hook "/opt/hooks/check_network.sh" \
  --post-hook "/opt/hooks/on_cert_change.sh"
```

---

## Hook-Vertrag (Umgebungsvariablen)

Beim Ausführen von `pre-hook` und `post-hook` setzt `adfs-cert-sync` hilfreiche Umgebungsvariablen:

* `ADFS_HOOK_PHASE`: `pre` oder `post`
* `ADFS_CERT_PATH`: Pfad zur zwischengespeicherten PEM-Datei
* `ADFS_CERT_CHANGED`: `1` bei Änderung, sonst `0`
* `ADFS_PREV_CERT_SHA256`: Vorheriger SHA-256-Fingerabdruck (falls vorhanden)
* `ADFS_CERT_SHA256`: SHA-256-Fingerabdruck des aktiven Zertifikats (im `post`-Hook)
* `ADFS_CERT_SUBJECT`: Subject-DN des aktiven Zertifikats (im `post`-Hook)
* `ADFS_CERT_ISSUER`: Issuer-DN des aktiven Zertifikats (im `post`-Hook)
* `ADFS_CERT_SERIAL`: Seriennummer des aktiven Zertifikats (im `post`-Hook)
* `ADFS_CERT_NOT_BEFORE`: Beginn der Gültigkeit (ISO-8601 UTC, im `post`-Hook)
* `ADFS_CERT_NOT_AFTER`: Ende der Gültigkeit (ISO-8601 UTC, im `post`-Hook)

### Beispiel: Post-Hook für `.env`-Aktualisierung und TYPO3-Cache

```bash
#!/usr/bin/env bash
set -euo pipefail

# Nur ausführen, wenn sich das Zertifikat wirklich geändert hat
if [ "${ADFS_CERT_CHANGED:-0}" != "1" ]; then
  exit 0
fi

APP_ENV="/var/www/mein-projekt/.env"
CERT_PEM="$(cat "$ADFS_CERT_PATH")"

# Beispiel: Zertifikat oder Pfad in Zielsystem übernehmen
# (für eine einzeilige Env-Variable z. B. Base64-kodiert oder als Datei referenziert)
CERT_B64="$(base64 -w 0 "$ADFS_CERT_PATH")"

python3 - "$APP_ENV" "$CERT_B64" <<'PY'
from pathlib import Path
import sys

env_path = Path(sys.argv[1])
cert_b64 = sys.argv[2]
lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []

updated = False
out = []
for line in lines:
    if line.startswith("ADFS_SIGNING_CERT_B64="):
        out.append(f'ADFS_SIGNING_CERT_B64="{cert_b64}"')
        updated = True
    else:
        out.append(line)

if not updated:
    out.append(f'ADFS_SIGNING_CERT_B64="{cert_b64}"')

env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY

# TYPO3-Cache leeren (Beispiel)
/var/www/mein-projekt/vendor/bin/typo3 cache:flush
```

---

## Verwendung mit Cronjobs

Cron bringt eine eigene, oft minimalistische Umgebung mit (`PATH`, Arbeitsverzeichnis `/`, keine aktive `.venv`). Verwende deshalb in Cronjobs **immer absolute Pfade** und idealerweise `flock`, damit zwei Läufe nicht gleichzeitig starten.

### Beispiel-Crontab (`crontab -e`)

Alle 15 Minuten prüfen, gegen parallele Läufe absichern und Ausgaben in eine Logdatei schreiben:

```cron
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

*/15 * * * * /usr/bin/flock -n /tmp/adfs-cert-sync.lock /opt/adfs-cert-sync/.venv/bin/adfs-cert-sync --env-file /opt/adfs-cert-sync/.env >> /var/log/adfs-cert-sync.log 2>&1
```

### Tipps für den Cron-Betrieb

* **Kein `cd` nötig:** Da `--env-file` und `ADFS_CERT_OUTPUT_PATH` absolut angegeben werden können, ist das Working Directory egal. Wenn du den Default (`.env` im Projektverzeichnis) nutzt, funktioniert der Aufruf über das absolute Binary `/opt/adfs-cert-sync/.venv/bin/adfs-cert-sync` ebenfalls zuverlässig.
* **Exit-Codes:**
  * `0`: Erfolgreich (`unchanged` oder `updated`)
  * `1`: Lauf fehlgeschlagen (Netzwerk, XML, Validierung, Storage oder Hook-Fehler)
  * `2`: Konfigurationsfehler
* **Logrotation:** Lege für `/var/log/adfs-cert-sync.log` eine `logrotate`-Regel an, damit die Logdatei auf Dauer nicht unbegrenzt wächst.

---

## Nutzung als Python-Library

```python
from pathlib import Path
from adfs_cert_sync import AppConfig, HookConfig, SyncStatus, sync_adfs_certificate

config = AppConfig(
    metadata_url="https://fs.beispiel.de/FederationMetadata/2007-06/FederationMetadata.xml",
    cert_output_path=Path("/tmp/adfs_signing_cert.pem"),
    env_file=None,
    hooks=HookConfig(post_hook="/opt/hooks/notify_app.sh", post_hook_only_on_change=True),
)

result = sync_adfs_certificate(config)
if result.status == SyncStatus.UPDATED:
    print("Neues Zertifikat gespeichert:", result.active_certificate.sha256_fingerprint)
```
