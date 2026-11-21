# Runs under system sh via sudo. Only execute a verified private copy.
set -eu
umask 077
stage=$(/usr/bin/mktemp -d /private/var/tmp/burniso-helper.XXXXXXXX)
trap '/bin/rm -rf "$stage"' EXIT
/bin/cp "$1" "$stage/raw-helper"
shift
/bin/chmod 700 "$stage/raw-helper"
/usr/bin/codesign --verify --strict -R='anchor apple generic and identifier "com.burniso.usb.raw-helper" and certificate leaf[subject.OU] = "TXF2V79Z6N" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' "$stage/raw-helper"
"$stage/raw-helper" "$@"
