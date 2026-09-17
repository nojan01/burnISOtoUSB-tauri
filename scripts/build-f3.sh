#!/bin/bash
# Build the separately licensed F3 executables without Homebrew or network access.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-$(rustc -vV | sed -n 's/^host: //p')}"
case "$TARGET" in
  aarch64-apple-darwin) ARCH=arm64; MIN=11.0 ;;
  x86_64-apple-darwin) ARCH=x86_64; MIN=10.15 ;;
  *) echo "F3 bundle: unsupported target $TARGET" >&2; exit 1 ;;
esac
BUILD="$ROOT/src-tauri/target/f3-$TARGET"
OUT="$ROOT/src-tauri/binaries"
mkdir -p "$BUILD" "$OUT" "$ROOT/src-tauri/resources"
cp "$ROOT/scripts/f3-argp-config.h" "$BUILD/config.h"
ARGP="$ROOT/vendor/argp-standalone"
F3="$ROOT/vendor/f3/src"
for TOOL in f3write f3read; do
  xcrun clang -arch "$ARCH" -mmacosx-version-min="$MIN" -O2 -std=c17 \
    -D_DARWIN_C_SOURCE -DHAVE_CONFIG_H=1 -I"$BUILD" -I"$ARGP" -I"$F3" \
    "$ARGP"/argp-{ba,eexst,fmtstream,help,parse,pv,pvh}.c \
    "$ARGP/mempcpy.c" "$ARGP/strchrnul.c" \
    "$F3/libutils.c" "$F3/libfile.c" "$F3/libflow.c" "$F3/$TOOL.c" \
    -o "$OUT/$TOOL-$TARGET"
done
# Corresponding sources and build instructions travel with every binary release.
COPYFILE_DISABLE=1 tar --no-xattrs --exclude='.DS_Store' -czf \
  "$ROOT/src-tauri/resources/f3-sources.tar.gz" -C "$ROOT" \
  vendor/f3 vendor/argp-standalone vendor/README.md \
  scripts/build-f3.sh scripts/f3-argp-config.h
