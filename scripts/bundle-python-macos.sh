#!/bin/bash
# Install the pinned, unprivileged Python runtime before signing the outer app.
set -euo pipefail
app="${1:?Expected path to the app bundle}"
identity="${2:?Expected Developer ID identity}"
version='3.11.18+20261110'
archive_name="cpython-${version}-aarch64-apple-darwin-install_only.tar.gz"
checksum='73f1ed14486aa278d331e95f7d6d452f5cfb69d90b418e26e62fd4846d53557d'
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
archive="$scratch/$archive_name"
if [[ -n "${BURNISO_PYTHON_ARCHIVE:-}" ]]; then
  cp "$BURNISO_PYTHON_ARCHIVE" "$archive"
else
  curl --fail --location --silent --show-error \
    "https://github.com/astral-sh/python-build-standalone/releases/download/20261110/$archive_name" \
    --output "$archive"
fi
printf '%s  %s\n' "$checksum" "$archive" | shasum -a 256 -c -
tar -xzf "$archive" -C "$scratch"
runtime="$app/Contents/Resources/python"
test ! -e "$runtime"
ditto "$scratch/python" "$runtime"
while IFS= read -r -d '' file; do
  if [[ "$(/usr/bin/file -b "$file")" == Mach-O* ]]; then
    codesign --force --options runtime --timestamp --sign "$identity" "$file"
  fi
done < <(find "$runtime" -type f -print0)
"$runtime/bin/python3" -I -S -c 'import ctypes, fcntl, hashlib, lzma, plistlib, selectors, subprocess'
