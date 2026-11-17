#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_DIR="$ROOT/skills/masvs"
VERSION="$(awk '
  /^---[[:space:]]*$/ { fm++; next }
  fm == 1 && /^metadata:/ { in_meta = 1; next }
  fm == 1 && in_meta && /^[^[:space:]]/ { in_meta = 0 }
  fm == 1 && in_meta && /^[[:space:]]+version:/ {
    v = $0; sub(/^[[:space:]]+version:[[:space:]]*/, "", v); gsub(/["'"'"'[:space:]]/, "", v)
    print v; exit
  }
' "$SKILL_DIR/SKILL.md")"

[ -n "$VERSION" ] || { echo "version not found in skills/masvs/SKILL.md" >&2; exit 1; }

if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  && [ -n "$(git -C "$ROOT" status --porcelain -- skills/masvs)" ]; then
  echo "skills/masvs/ has uncommitted changes; commit or stash them before packaging" >&2
  exit 1
fi

mkdir -p "$ROOT/dist"
OUT="$ROOT/dist/masvs-$VERSION.zip"
rm -f "$OUT"
(cd "$ROOT/skills" && zip -qr "$OUT" masvs -x '*/__pycache__/*' '*.pyc' '*.DS_Store' '*/.gitkeep')
echo "$OUT"
