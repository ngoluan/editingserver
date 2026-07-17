#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-/home/luanngo/taco}"
OUTPUT_DIR="${2:-/home/luanngo/server}"
OUTPUT_FILE="${OUTPUT_DIR}/taco_combined-source.txt"

: > "${OUTPUT_FILE}"

find "$SRC_DIR" -type f \
  \( \
    -name "*.js" -o -name "*.mjs" \
    -o -name "*.py" \
    -o -name "*.css" \
    -o -name "*.html" \
    -o -name "*.json" \
    -o -name "*.yaml" \
    -o -name "*.xml" \
    -o -name "*.sh" \
    -o -name "*.md" \
    -o -name "*.ejs" \
    -o -name "*.env" \
    -o -name "*.conf" \
    -o -name "*.ini" \
  \) \
  ! -path "*/node_modules/*" \
  ! -path "*/.git/*" \
  ! -path "*/build/*" \
  ! -path "*/dist/*" \
  ! -path "*/target/*" \
  ! -path "*/__pycache__/*" \
  ! -path "*/venv/*" \
  ! -path "*/vendor/*" \
  ! -path "*/coverage/*" \
  ! -path "*/tmp/*" \
  ! -path "*/old/*" \
  ! -path "*/archive/*" \
  ! -path "*/.next/*" \
  ! -path "*/.nuxt/*" \
  ! -path "*/.gradle/*" \
  ! -path "*/.backup/*" \
  ! -path "*/data/*" \
  ! -path "*/patches/*" \
  ! -path "*/.wwebjs_cache/*" \
  ! -path "*/temp/*" \
  ! -path "*/listings/*" \
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
    echo "// ===== $f (${mod%%.*}) =====" >> "${OUTPUT_FILE}"
    cat "$f" >> "${OUTPUT_FILE}"
    echo "" >> "${OUTPUT_FILE}"
  done

echo "Done. Combined $(wc -l < "${OUTPUT_FILE}") lines into ${OUTPUT_FILE}"
