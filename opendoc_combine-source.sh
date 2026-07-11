#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-/home/luanngo/opendoc}"
OUTPUT_DIR="${2:-/home/luanngo/server}"
OUTPUT_FILE="$OUTPUT_DIR/opendoc_combined-source.txt"

: > "$OUTPUT_FILE"

find "$SRC_DIR" -type f \
  ! -path "*/node_modules/*" \
  ! -path "*/.git/*" \
  ! -path "*/target/*" \
  ! -path "*/build/*" \
  ! -path "*/dist/*" \
  ! -path "*/venv/*" \
  ! -path "*/__pycache__/*" \
  ! -path "*/tmp/*" \
  ! -path "*/.backup/*" \
  ! -path "*/data/*" \
  ! -path "*/patches/*" \
  ! -name "package-lock.json" \
  ! -name "yarn.lock" \
  ! -name "*.svg" \
  ! -name "*.png" \
  ! -name "*.jpg" \
  ! -name "*.gif" \
  ! -name "*.ico" \
  | sort \
  | while read -r f; do
    rel="${f#$SRC_DIR/}"
    echo "// ===== $rel =====" >> "$OUTPUT_FILE"
    cat "$f" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
  done

echo "Done. Combined $(wc -l < "$OUTPUT_FILE") lines into $OUTPUT_FILE"
