#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-/Users/seconduser/StudioProjects/echo}"
OUTPUT_DIR="${2:-/Users/seconduser/StudioProjects/editingserver}"
OUTPUT_FILE="$OUTPUT_DIR/echo_combined-source.txt"

: > "$OUTPUT_FILE"

find "$SRC_DIR" -type f \( \
  -name "*.ts" -o \
  -name "*.py" -o \
  -name "*.css" -o \
  -name "*.html" -o \
  -name "*.gd" \
\) \
  ! -path "*/tmp/*" \
  ! -path "*/node_modules/*" \
  ! -path "*/dist/*" \
  ! -name "package-lock.json" \
  ! -name "yarn.lock" \
  ! -name "pnpm-lock.yaml" \
  ! -name "bun.lock" \
  ! -name "Cargo.lock" \
  ! -name "Gemfile.lock" \
  ! -name "poetry.lock" \
  ! -name "composer.lock" \
  ! -name "*.svg" \
  ! -name "*.png" \
  ! -name "*.jpg" \
  ! -name "*.jpeg" \
  ! -name "*.gif" \
  ! -name "*.ico" \
  ! -name "*.woff" \
  ! -name "*.woff2" \
  ! -name "*.ttf" \
  ! -name "*.eot" \
  ! -name "*.pdf" \
  ! -name "*.zip" \
  ! -name "*.gz" \
  ! -name "*.tar" \
  ! -name "*.tgz" \
  ! -name "*.jar" \
  ! -name "*.class" \
  ! -name "*.pyc" \
  ! -name "*.pyo" \
  ! -name "*.so" \
  ! -name "*.dll" \
  ! -name "*.dylib" \
  ! -name "*.exe" \
  ! -name "*.obj" \
  ! -name "*.o" \
  | sort \
  | while read -r f; do
    rel="${f#$SRC_DIR/}"
    echo "// ===== $rel =====" >> "$OUTPUT_FILE"
    cat "$f" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
  done

echo "Done. Combined $(wc -l < "$OUTPUT_FILE") lines into $OUTPUT_FILE"
