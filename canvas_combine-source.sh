#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-$HOME/canvasforge}"
OUTPUT_DIR="${2:-$HOME/server}"
OUTPUT_FILE="$OUTPUT_DIR/canvas_combined-source.txt"

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

# Source files
find "$SRC_DIR/src" -type f \( -name '*.jsx' -o -name '*.js' -o -name '*.css' \) | sort | while read -r f; do append "$f"; done

# Config files
for f in "$SRC_DIR/package.json" "$SRC_DIR/vite.config.js" "$SRC_DIR/index.html"; do
    [ -f "$f" ] && append "$f"
done

line_count=$(wc -l < "$OUTPUT_FILE")
size=$(du -h "$OUTPUT_FILE" | cut -f1)
echo "Done — $line_count lines, $size written to $OUTPUT_FILE"
