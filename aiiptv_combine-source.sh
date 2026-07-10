#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-$HOME/aiiptv}"
OUTPUT_DIR="${2:-$HOME/server}"
OUTPUT_FILE="$OUTPUT_DIR/aiiptv_combined-source.txt"

echo "Combining source from: $SRC_DIR"
echo "Output: $OUTPUT_FILE"

rm -f "$OUTPUT_FILE"
touch "$OUTPUT_FILE"

append() {
    local file="$1"
    local rel="${file#$SRC_DIR/}"
    echo "" >> "$OUTPUT_FILE"
    printf '%*s\n' 80 '' | tr ' ' '=' >> "$OUTPUT_FILE"
    echo "// FILE: $rel" >> "$OUTPUT_FILE"
    printf '%*s\n' 80 '' | tr ' ' '=' >> "$OUTPUT_FILE"
    cat "$file" >> "$OUTPUT_FILE"
}

export -f append
export SRC_DIR OUTPUT_FILE

# Android Kotlin source
find "$SRC_DIR/app/src" -type f \( -name '*.kt' -o -name '*.xml' \) ! -path '*/res/values/*' | sort | while read -r f; do append "$f"; done

# Android resources (values - strings, colors, themes)
for f in "$SRC_DIR/app/src/main/res/values/strings.xml" "$SRC_DIR/app/src/main/res/values/colors.xml" "$SRC_DIR/app/src/main/res/values/themes.xml"; do
    [ -f "$f" ] && append "$f"
done

# Server TypeScript source
find "$SRC_DIR/server/src" -type f -name '*.ts' | sort | while read -r f; do append "$f"; done

# Server Prisma schema
[ -f "$SRC_DIR/server/prisma/schema.prisma" ] && append "$SRC_DIR/server/prisma/schema.prisma"

# Server config files
for f in "$SRC_DIR/server/package.json" "$SRC_DIR/server/tsconfig.json" "$SRC_DIR/server/.env.example"; do
    [ -f "$f" ] && append "$f"
done

# Server scripts
find "$SRC_DIR/server/scripts" -type f | sort | while read -r f; do append "$f"; done

# Root Gradle build files
for f in "$SRC_DIR/build.gradle.kts" "$SRC_DIR/settings.gradle.kts" "$SRC_DIR/gradle.properties" "$SRC_DIR/app/build.gradle.kts" "$SRC_DIR/app/proguard-rules.pro"; do
    [ -f "$f" ] && append "$f"
done

# Gradle version catalog
[ -f "$SRC_DIR/gradle/libs.versions.toml" ] && append "$SRC_DIR/gradle/libs.versions.toml"
[ -f "$SRC_DIR/gradle/wrapper/gradle-wrapper.properties" ] && append "$SRC_DIR/gradle/wrapper/gradle-wrapper.properties"

line_count=$(wc -l < "$OUTPUT_FILE")
size=$(du -h "$OUTPUT_FILE" | cut -f1)
echo "Done — $line_count lines, $size written to $OUTPUT_FILE"
