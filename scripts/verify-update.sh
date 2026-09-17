#!/bin/bash
# Non-mutating release gate: extract into a unique scratch app and assess it.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
archive="${1:?Usage: verify-update.sh ARCHIVE EXPECTED_VERSION}"
expected="${2:?Expected version required}"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/burniso-update-check.XXXXXX")"
# Scratch is deliberately retained on failure for inspection; never an installed app.
app="$scratch/BurnISO to USB.app"
cargo run --offline --quiet --manifest-path src-tauri/Cargo.toml --example verify_update_archive -- "$archive" "$app"
actual="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")"
test "$actual" = "$expected" || { echo "Version mismatch: $actual != $expected" >&2; exit 1; }
codesign --verify --strict --deep "$app"
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
echo "Updater archive verified (version, Rust extraction, signature, ticket, Gatekeeper): $app"
