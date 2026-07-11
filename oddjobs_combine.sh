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
  ! -name "package-lock.json" \
  | sort \
  | while read -r f; do
    rel="${f#$SRC_DIR/}"
    echo "// ===== $rel =====" >> "$OUTPUT"
    cat "$f" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
  done

echo "Done. Combined $(wc -l < "$OUTPUT") lines into $OUTPUT"
