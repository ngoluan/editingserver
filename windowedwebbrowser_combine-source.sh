#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-/Users/seconduser/StudioProjects/WindowWeb}"
OUTPUT_DIR="${2:-/Users/seconduser/StudioProjects/editingserver}"
OUTPUT_FILE="$OUTPUT_DIR/windowedwebbrowser_combined-source.txt"

: > "$OUTPUT_FILE"

find "$SRC_DIR" -type f \( \
  -name "*.kts" -o \
  -name "*.html" \
\) \
  ! -path "*/tmp/*" \
  ! -path "*/old/*" \
  ! -path "*/archive/*" \
  ! -path "*/build/*" \
  ! -path "*/local.properties/*" \
  ! -path "*/captures/*" \
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
    mod=$(stat -c '%y' "$f")
    echo "// ===== $f (${mod%%.*}) =====" >> "$OUTPUT_FILE"
    cat "$f" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
  done

echo "Done. Combined $(wc -l < "$OUTPUT_FILE") lines into $OUTPUT_FILE"
