#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="/home/luanngo/oddjobs"
OUT_DIR="/home/luanngo/server"
OUTPUT="$OUT_DIR/oddjobs_combined-source.txt"

: > "$OUTPUT"

find "$SRC_DIR" -type f \
  \( -name "*.js" -o -name "*.mjs" -o -name "*.ejs" -o -name "*.css" -o -name "*.json" \) \
  ! -path "*/node_modules/*" \
  ! -path "*/.git/*" \
  ! -path "*/data/*" \
  ! -path "*/tmp/*" \
  ! -path "*/old/*" \
  ! -path "*/archive/*" \
  ! -name "package-lock.json" \
  | sort \
  | while read -r f; do
    mod=$(stat -c '%y' "$f")
    echo "// ===== $f (${mod%%.*}) =====" >> "$OUTPUT"
    cat "$f" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  done

echo "Done. Combined $(wc -l < "$OUTPUT") lines into $OUTPUT"
