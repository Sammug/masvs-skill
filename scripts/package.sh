#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(awk '
  /^---[[:space:]]*$/ { fm++; next }
  fm == 1 && /^metadata:/ { in_meta = 1; next }
  fm == 1 && in_meta && /^[^[:space:]]/ { in_meta = 0 }
  fm == 1 && in_meta && /^[[:space:]]+version:/ {
    v = $0; sub(/^[[:space:]]+version:[[:space:]]*/, "", v); gsub(/["'"'"'[:space:]]/, "", v)
    print v; exit
  }
' "$ROOT/masvs/SKILL.md")"

[ -n "$VERSION" ] || { echo "version not found in masvs/SKILL.md" >&2; exit 1; }

mkdir -p "$ROOT/dist"
OUT="$ROOT/dist/masvs-$VERSION.zip"
rm -f "$OUT"
(cd "$ROOT" && zip -qr "$OUT" masvs -x '*/__pycache__/*' '*.pyc' '*.DS_Store')
echo "$OUT"
