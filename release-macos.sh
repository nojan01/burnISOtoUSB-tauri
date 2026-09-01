#!/bin/bash
# Baut, signiert und notarisiert "BurnISO to USB" fuer macOS.
#
# Reihenfolge bewusst so gewaehlt:
#   1. App bauen, notarisieren, stapeln.
#   2. Updater-Archiv und DMG erst aus der GESTAPELTEN App erzeugen.
# Nur so tragen beide Auslieferungswege das Notarisierungsticket, und die
# Signatur bleibt auch ohne Netzverbindung pruefbar.
#
# Die Sonderbehandlung des Updater-Archivs (Contents statt .app als oberster
# Eintrag, COPYFILE_DISABLE, --no-xattrs) ist in RELEASING.md begruendet.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
IDENTITY="Developer ID Application: Norbert Jander (TXF2V79Z6N)"
NOTARY_PROFILE="${NOTARY_PROFILE:-DesktopProfileManager}"
APP_NAME="BurnISO to USB"
VERSION="$(node -p "require('$PROJECT_DIR/package.json').version")"
BUNDLE_DIR="$PROJECT_DIR/src-tauri/target/release/bundle"
MACOS_DIR="$BUNDLE_DIR/macos"
APP_PATH="$MACOS_DIR/${APP_NAME}.app"
DMG_DIR="$BUNDLE_DIR/dmg"
DMG_PATH="$DMG_DIR/${APP_NAME}_${VERSION}_aarch64.dmg"
UPDATER_TGZ="$MACOS_DIR/BurnISO.to.USB.app.tar.gz"
MANIFEST="$MACOS_DIR/latest.json"
NOTARY_ZIP="$BUNDLE_DIR/${APP_NAME}_${VERSION}_aarch64-notarization.zip"
SIGNING_KEY="$HOME/.tauri/burniso-usb-updater.key"
STAGING_DIR="$(mktemp -d /tmp/burniso-dmg.XXXXXX)"

cleanup() {
  rm -rf -- "$STAGING_DIR"
  rm -f -- "$NOTARY_ZIP"
}
trap cleanup EXIT

[ -f "$SIGNING_KEY" ] || { echo "Updater-Schluessel fehlt: $SIGNING_KEY" >&2; exit 1; }

cd "$PROJECT_DIR"

echo "==> Baue ${APP_NAME} ${VERSION}"
TAURI_SIGNING_PRIVATE_KEY="$SIGNING_KEY" \
TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
  npm run tauri -- build --bundles app

echo "==> Signiere die App"
codesign --force --deep --options runtime --timestamp \
  --sign "$IDENTITY" "$APP_PATH"
codesign --verify --deep --strict --verbose=2 "$APP_PATH"

echo "==> Notarisiere die App"
ditto -c -k --keepParent "$APP_PATH" "$NOTARY_ZIP"
xcrun notarytool submit "$NOTARY_ZIP" \
  --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$APP_PATH"
xcrun stapler validate "$APP_PATH"
spctl --assess --type execute --verbose=2 "$APP_PATH"

echo "==> Erzeuge das Updater-Archiv aus der gestapelten App"
rm -f -- "$UPDATER_TGZ" "$UPDATER_TGZ.sig"
COPYFILE_DISABLE=1 tar --no-xattrs -C "$MACOS_DIR" \
  -czf "$UPDATER_TGZ" "${APP_NAME}.app/Contents"
TAURI_SIGNING_PRIVATE_KEY_PATH="$SIGNING_KEY" \
TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
  npm run tauri -- signer sign "$UPDATER_TGZ"

echo "==> Erstelle das DMG aus der gestapelten App"
mkdir -p "$DMG_DIR"
ditto "$APP_PATH" "$STAGING_DIR/${APP_NAME}.app"
ln -s /Applications "$STAGING_DIR/Applications"
rm -f -- "$DMG_PATH"
hdiutil create -volname "$APP_NAME" -srcfolder "$STAGING_DIR" \
  -ov -format UDZO "$DMG_PATH"

echo "==> Signiere und notarisiere das DMG"
codesign --force --timestamp --sign "$IDENTITY" "$DMG_PATH"
codesign --verify --deep --strict --verbose=2 "$DMG_PATH"
xcrun notarytool submit "$DMG_PATH" \
  --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple "$DMG_PATH"
xcrun stapler validate "$DMG_PATH"
spctl --assess --type open --context context:primary-signature \
  --verbose=2 "$DMG_PATH"

echo "==> Erzeuge das Update-Manifest"
npm run make-updater-manifest -- "$VERSION" darwin-aarch64 \
  "$UPDATER_TGZ" "$MANIFEST"

echo
echo "Fertig. Release-Artefakte:"
echo "  $DMG_PATH"
echo "  $UPDATER_TGZ"
echo "  $UPDATER_TGZ.sig"
echo "  $MANIFEST"
