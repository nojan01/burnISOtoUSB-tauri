#!/bin/bash
# Compatibility entry point. The canonical release script uses a notarytool profile.
set -euo pipefail
if [[ "${1:-}" == "--reset" ]]; then
  legacy_service="BurnISOtoUSB Notarisierung"
  if /usr/bin/security find-generic-password -s "$legacy_service" >/dev/null 2>&1; then
    /usr/bin/security delete-generic-password -s "$legacy_service"
  fi
  echo "Alten Zugangsdaten-Eintrag entfernt, sofern vorhanden."
  exit 0
fi
if (( $# )); then
  echo "Unbekannte Option: $1" >&2
  exit 1
fi
exec /bin/bash "$(dirname "$0")/../release-macos.sh"
