#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-/home/luanngo/boss}"
OUTPUT_DIR="${2:-/home/luanngo/server}"
OUTPUT_FILE="${OUTPUT_DIR}/boss_combined-source.txt"

: > "${OUTPUT_FILE}"

find "$SRC_DIR" -type f \( \
    -name "*.ts" -o -name "*.js" -o -name "*.jsx" -o -name "*.mjs" \
    -o -name "*.py" -o -name "*.java" -o -name "*.swift" -o -name "*.m" \
    -o -name "*.css" -o -name "*.html" -o -name "*.json" -o -name "*.xml" \
    -o -name "*.prisma" -o -name "*.sql" -o -name "*.sh" -o -name "*.bat" \
    -o -name "*.gradle" -o -name "*.properties" -o -name "*.conf" \
    -o -name "*.env" -o -name "*.ini" -o -name "*.toml" -o -name "*.yml" \
    -o -name "*.yaml" -o -name "*.txt" \
    -o -name "*.plist" -o -name "*.podspec" -o -name "*.storyboard" \
    -o -name "*.entitlements" -o -name "*.xcscheme" -o -name "*.pbxproj" \
    -o -name "*.iml" -o -name "*.gitignore" -o -name "*.development" \
    -o -name "*.clinerules" -o -name "*.cursorrules" -o -name "*.codex" \
    -o -name "Dockerfile" -o -name "Makefile" -o -name "Podfile" \
    -o -name "README" -o -name "gradlew" \
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
  ! -path "*/test-results/*" \
  ! -path "*/docs/*" \
  ! -path "*/migrations/*" \
  ! -path "*/tmp/*" \
  ! -path "*/old/*" \
  ! -path "*/archive/*" \
  ! -path "*/.next/*" \
  ! -path "*/.nuxt/*" \
  ! -path "*/.gradle/*" \
  ! -path "*/.claude/*" \
  ! -path "*/.vscode/*" \
  ! -path "*/.kilo/*" \
  ! -path "*/.dependencygraph/*" \
  ! -path "*/.backup/*" \
  ! -path "*/data/*" \
  ! -path "*/uploads/*" \
  ! -path "*/logs/*" \
  ! -path "*/models/*" \
  ! -path "*/patches/*" \
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

echo "Done. Combined $(wc -l < "${OUTPUT_FILE}") lines into ${OUTPUT_FILE}"
