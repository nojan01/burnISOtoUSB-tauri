#!/bin/bash
# Baut BurnISO to USB signiert und notarisiert und prueft das Ergebnis nach.
#
# Ohne dieses Skript ist der Fallstrick gross: "npm run tauri -- build" baut
# klaglos durch, ueberspringt die Notarisierung aber wortlos, sobald die
# Apple-Variablen fehlen. Das Ergebnis sieht fertig aus und wird auf fremden
# Rechnern trotzdem von Gatekeeper abgewiesen.
#
# Die Zugangsdaten liegen im Schluesselbund und werden beim ersten Lauf einmalig
# abgefragt.
#
# Aufruf:
#   scripts/release-macos.sh              bauen, signieren, notarisieren
#   scripts/release-macos.sh --reset      hinterlegte Zugangsdaten loeschen
set -euo pipefail

SERVICE="BurnISOtoUSB Notarisierung"
APP_NAME="BurnISO to USB"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for arg in "$@"; do
  case "$arg" in
    --reset)
      security delete-generic-password -s "$SERVICE" >/dev/null 2>&1 &&
        echo "Hinterlegte Zugangsdaten geloescht." ||
        echo "Es waren keine Zugangsdaten hinterlegt."
      exit 0
      ;;
    *)
      echo "Unbekannte Option: $arg (erlaubt: --reset)" >&2
      exit 1
      ;;
  esac
done

conf="src-tauri/tauri.conf.json"

# Signaturkennung und Team-ID kommen aus der Projektkonfiguration, damit hier
# keine zweite Stelle entsteht, die bei einem Zertifikatswechsel nachzuziehen
# waere.
identity="$(sed -n 's/.*"signingIdentity"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' "$conf")"
if [ -z "$identity" ]; then
  echo "In $conf ist keine signingIdentity eingetragen." >&2
  exit 1
fi

team="$(printf '%s' "$identity" | sed -n 's/.*(\([A-Z0-9]*\))$/\1/p')"
if [ -z "$team" ]; then
  echo "Aus der signingIdentity laesst sich keine Team-ID lesen: $identity" >&2
  exit 1
fi

if ! grep -qF "$identity" <<<"$(security find-identity -v -p codesigning)"; then
  echo "Das Zertifikat \"$identity\" liegt nicht im Schluesselbund." >&2
  echo "Ohne gueltiges Zertifikat kann weder signiert noch notarisiert werden." >&2
  exit 1
fi

# Apple-ID steht im Feld "acct" des Schluesselbundeintrags. Fehlt der Eintrag,
# endet "security" mit einem Fehler; wegen "set -e" muss das hier ausdruecklich
# abgefangen werden, sonst braeche das Skript beim ersten Lauf wortlos ab.
apple_id="$(security find-generic-password -s "$SERVICE" 2>/dev/null |
  awk -F'"' '/"acct"<blob>=/ {print $4}' || true)"

if [ -n "$apple_id" ]; then
  apple_password="$(security find-generic-password -s "$SERVICE" -w)"
  echo "Zugangsdaten aus dem Schluesselbund: $apple_id"
else
  echo "Fuer die Notarisierung werden Apple-ID und ein app-spezifisches Passwort"
  echo "gebraucht (appleid.apple.com -> Anmeldung & Sicherheit)."
  echo
  read -r -p "Apple-ID: " apple_id
  read -r -s -p "App-spezifisches Passwort: " apple_password
  echo

  if [ -z "$apple_id" ] || [ -z "$apple_password" ]; then
    echo "Eingabe unvollstaendig." >&2
    exit 1
  fi

  # Erst pruefen, dann hinterlegen. Sonst landet ein Tippfehler dauerhaft im
  # Schluesselbund und der naechste Lauf scheitert erst nach dem langen Build.
  echo "Pruefe die Zugangsdaten bei Apple ..."
  if ! xcrun notarytool history \
    --apple-id "$apple_id" --password "$apple_password" --team-id "$team" \
    >/dev/null 2>&1; then
    echo "Apple weist die Zugangsdaten zurueck. Nichts hinterlegt." >&2
    exit 1
  fi

  security add-generic-password -U -s "$SERVICE" -a "$apple_id" \
    -w "$apple_password" -T /usr/bin/security \
    -j "Notarisierung von $APP_NAME (app-spezifisches Passwort)"
  echo "Zugangsdaten im Schluesselbund hinterlegt."
fi

version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' "$conf" | head -1)"
echo
echo "Baue $APP_NAME $version"
echo "Signatur: $identity"
echo

# Tauri signiert, notarisiert und stapelt das Ticket selbst, sobald diese drei
# Variablen gesetzt sind. Es notarisiert dabei die .app vor dem Packen, deshalb
# enthaelt auch das DMG bereits eine gestapelte App.
export APPLE_SIGNING_IDENTITY="$identity"
export APPLE_ID="$apple_id"
export APPLE_PASSWORD="$apple_password"
export APPLE_TEAM_ID="$team"

# Schluessel fuer die Updater-Signatur. Er ist unabhaengig vom Apple-Zertifikat
# und beweist der installierten App, dass ein Update wirklich von hier stammt.
# Ohne diese Variable baut Tauri zwar, erzeugt aber keine .sig-Datei.
# Tauri erwartet den Schluessel in TAURI_SIGNING_PRIVATE_KEY und akzeptiert
# dort auch einen Dateipfad; die Variante mit _PATH allein genuegt nicht.
updater_key="$HOME/.tauri/burniso-usb-updater.key"
if [ ! -f "$updater_key" ]; then
  echo "Updater-Schluessel fehlt: $updater_key" >&2
  echo "Neu erzeugen mit: npx tauri signer generate --write-keys \"$updater_key\"" >&2
  exit 1
fi
export TAURI_SIGNING_PRIVATE_KEY="$updater_key"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""

npm run tauri -- build

app="src-tauri/target/release/bundle/macos/${APP_NAME}.app"
dmg="src-tauri/target/release/bundle/dmg/${APP_NAME}_${version}_aarch64.dmg"

for pfad in "$app" "$dmg"; do
  if [ ! -e "$pfad" ]; then
    echo "Erwartetes Ergebnis fehlt: $pfad" >&2
    exit 1
  fi
done

# bundle_dmg.sh legt `.VolumeIcon.icns` als technische Datei im Image ab.
# Finder zeigt sie bei global aktivierter Anzeige versteckter Dateien selbst
# mit gesetztem `hidden`-Attribut. Deshalb wird sie vollstaendig entfernt und
# das Custom-Icon-Flag des Volumes geloescht. Das komprimierte Image dazu kurz
# schreibbar konvertieren und anschliessend erneut komprimieren und signieren.
# Die bereits notarisierten Inhalte der App bleiben unveraendert.
echo
echo "Entferne die technische Volume-Icon-Datei aus dem DMG ..."
dmg_scratch="$(mktemp -d "${TMPDIR:-/tmp}/burniso-dmg.XXXXXX")"
dmg_rw="$dmg_scratch/rw.dmg"
dmg_final="$dmg_scratch/final.dmg"
dmg_mount="$dmg_scratch/mount"
mkdir "$dmg_mount"
cleanup_dmg_scratch() {
  if mount | grep -Fq " on $dmg_mount "; then
    hdiutil detach "$dmg_mount" >/dev/null 2>&1 || true
  fi
  rm -rf "$dmg_scratch"
}
trap cleanup_dmg_scratch EXIT INT TERM
hdiutil convert "$dmg" -format UDRW -o "$dmg_rw" >/dev/null
hdiutil attach "$dmg_rw" -mountpoint "$dmg_mount" -nobrowse -noverify -noautoopen >/dev/null
if [ -f "$dmg_mount/.VolumeIcon.icns" ]; then
  rm "$dmg_mount/.VolumeIcon.icns"
fi
SetFile -a c "$dmg_mount"
sync
hdiutil detach "$dmg_mount" >/dev/null
hdiutil convert "$dmg_rw" -format UDZO -imagekey zlib-level=9 -o "$dmg_final" >/dev/null
mv "$dmg_final" "$dmg"
codesign --force --timestamp --sign "$identity" "$dmg"
trap - EXIT INT TERM
rm -rf "$dmg_scratch"

# Tauri notarisiert nur die .app und stapelt das Ticket auch nur dort. Das DMG
# wird zwar signiert, bleibt aber ohne Ticket - beim Oeffnen einer geladenen
# Datei prueft Gatekeeper jedoch zuerst das DMG. Es wird deshalb hier getrennt
# eingereicht und gestapelt.
echo
echo "Reiche das DMG zur Notarisierung ein ..."
xcrun notarytool submit "$dmg" \
  --apple-id "$apple_id" --password "$apple_password" --team-id "$team" \
  --wait
xcrun stapler staple "$dmg"

echo
echo "=== Nachpruefung ==="

fail=0
check() {
  label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "  ok   $label"
  else
    echo "  FEHL $label"
    fail=1
  fi
}

check "Signatur der App gueltig" codesign --verify --strict --deep "$app"
check "Ticket in der App gestapelt" xcrun stapler validate "$app"
check "Ticket im DMG gestapelt" xcrun stapler validate "$dmg"

# Gatekeeper-Gegenprobe: Bei einer notarisierten App meldet spctl
# "source=Notarized Developer ID".
verdict="$(spctl -a -vvv -t install "$app" 2>&1 || true)"
if grep -q "source=Notarized Developer ID" <<<"$verdict"; then
  echo "  ok   Gatekeeper: Notarized Developer ID"
else
  echo "  FEHL Gatekeeper: $(tr '\n' ' ' <<<"$verdict")"
  fail=1
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "Es sind Pruefungen fehlgeschlagen, das Paket ist nicht auslieferbar." >&2
  exit 1
fi

echo "Fertig signiert und notarisiert:"
echo "  $dmg"

# Ohne Manifest kann der eingebaute Updater das Paket nicht anbieten; es wird
# deshalb bei jedem Release miterzeugt.
updater_archive="src-tauri/target/release/bundle/macos/${APP_NAME}.app.tar.gz"
if [ ! -f "$updater_archive" ]; then
  echo
  echo "Updater-Archiv fehlt: $updater_archive" >&2
  echo "Ist \"createUpdaterArtifacts\" in $conf aktiviert?" >&2
  exit 1
fi
npm run --silent make-updater-manifest -- \
  "$version" darwin-aarch64 "$updater_archive" latest.json
echo
echo "Fuer das GitHub-Release hochladen:"
echo "  $dmg"
echo "  $updater_archive"
echo "  ${updater_archive}.sig"
echo "  latest.json"
