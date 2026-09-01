# macOS-Release mit Auto-Update

Die automatische Aktualisierung verwendet das von Tauri signierte
`*.app.tar.gz`-Archiv, **nicht** die DMG. Die DMG bleibt für die manuelle
Installation erhalten.

## Voraussetzungen

- Der private Updater-Schlüssel liegt ausschließlich lokal unter
  `~/.tauri/burniso-usb-updater.key` und darf niemals ins Repository oder in
  einen GitHub-Release gelangen.
- Das Developer-ID-Zertifikat und das Notarisierungsprofil
  `DesktopProfileManager` sind im Schlüsselbund vorhanden. Ein früher hier
  genanntes Profil `burniso-notary` existiert nicht mehr und wird von Apple
  mit HTTP 401 abgewiesen.

## Release erstellen

Der gesamte unten beschriebene Ablauf steckt in `./release-macos.sh`. Das
Skript ist der empfohlene Weg; die folgenden Abschnitte erklären, was es tut
und warum.

Ersetze `1.4.3` durch die neue, bereits in `package.json`, `Cargo.toml` und
`tauri.conf.json` eingetragene Version.

```zsh
export TAURI_SIGNING_PRIVATE_KEY="$HOME/.tauri/burniso-usb-updater.key"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""
npm run tauri -- build
```

Der Build erzeugt unter `src-tauri/target/release/bundle/macos/` mindestens:

- `BurnISO to USB.app.tar.gz` und `BurnISO to USB.app.tar.gz.sig` für den Updater
- eine DMG für die manuelle Installation

Notarisiere und staple sowohl die App als auch die DMG mit dem Keychain-Profil
`DesktopProfileManager`. Wichtig ist die Reihenfolge: erst die App notarisieren
und stapeln, **danach** Updater-Archiv und DMG aus der gestapelten App
erzeugen. Nur so tragen beide Auslieferungswege das Ticket und lassen sich
offline prüfen. Das neu erzeugte Archiv darf **keinen** separaten obersten
`.app`-Verzeichniseintrag enthalten:

```zsh
COPYFILE_DISABLE=1 tar --no-xattrs -C "src-tauri/target/release/bundle/macos" \
  -czf "src-tauri/target/release/bundle/macos/BurnISO.to.USB.app.tar.gz" \
  "BurnISO to USB.app/Contents"

TAURI_SIGNING_PRIVATE_KEY_PATH="$HOME/.tauri/burniso-usb-updater.key" \
TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
  npm run tauri -- signer sign \
  "src-tauri/target/release/bundle/macos/BurnISO.to.USB.app.tar.gz"
```

Tauri entfernt beim Installieren bereits die oberste App-Ebene. Ein leeres
`.app`-Verzeichnis als eigener Tar-Eintrag würde deshalb das Entpacken des
Updates abbrechen. Die Optionen `COPYFILE_DISABLE=1` und `--no-xattrs` sind
ebenfalls zwingend: Ohne sie können macOS-Metadatendateien (`._*`) im
installierten Bundle entstehen und dessen Code-Signatur ungültig machen.
Anschließend das Update-Manifest erzeugen:

```zsh
npm run make-updater-manifest -- 1.4.3 darwin-aarch64 \
  "src-tauri/target/release/bundle/macos/BurnISO.to.USB.app.tar.gz" \
  "src-tauri/target/release/bundle/macos/latest.json"
```

Lade bei **jedem** Release die DMG, das `.app.tar.gz`, dessen `.sig` und
`latest.json` als Assets des GitHub-Releases hoch. Das Asset `latest.json`
muss im neuesten veröffentlichten Release liegen; die App ruft es über
`releases/latest/download/latest.json` ab.

```zsh
gh release upload v1.4.3 \
  "src-tauri/target/release/bundle/dmg/BurnISO to USB_1.4.3_aarch64.dmg" \
  "src-tauri/target/release/bundle/macos/BurnISO.to.USB.app.tar.gz" \
  "src-tauri/target/release/bundle/macos/BurnISO.to.USB.app.tar.gz.sig" \
  "src-tauri/target/release/bundle/macos/latest.json"
```

Eine App ohne den Updater (bis einschließlich 1.4.2) kann sich nicht selbst
auf diese erste Version aktualisieren. Sie muss einmalig manuell installiert
werden. Danach stehen „Nach Updates suchen…“ und die Prüfung beim Start zur
Verfügung.
