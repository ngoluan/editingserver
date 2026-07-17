#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="${1:-$HOME/echo/godot/echo-godot-phase1-14/echo-godot-phase1-14}"
OUTPUT_DIR="${2:-$HOME/server}"
OUTPUT_FILE="$OUTPUT_DIR/echo-combined-source.txt"

echo "Combining source from: $SRC_DIR"
echo "Output: $OUTPUT_FILE"

rm -f "$OUTPUT_FILE"
touch "$OUTPUT_FILE"

append() {
    local file="$1"
    local mod=$(stat -c '%y' "$file")
    echo "" >> "$OUTPUT_FILE"
    printf '%*s\n' 80 '' | tr ' ' '=' >> "$OUTPUT_FILE"
    echo "// FILE: $file (${mod%%.*})" >> "$OUTPUT_FILE"
    printf '%*s\n' 80 '' | tr ' ' '=' >> "$OUTPUT_FILE"
    cat "$file" >> "$OUTPUT_FILE"
}

export -f append
export SRC_DIR OUTPUT_FILE

# Godot source files (GDScript, scenes, resources, data)
find "$SRC_DIR" -type f \( \
    -name '*.gd' -o \
    -name '*.tscn' -o \
    -name '*.tres' -o \
    -name '*.json' -o \
    -name '*.cfg' -o \
    -name '*.md' \
\) \
  ! -path "*/tmp/*" \
  ! -path "*/old/*" \
  ! -path "*/archive/*" \
| sort | while read -r f; do append "$f"; done

# project.godot
[ -f "$SRC_DIR/project.godot" ] && append "$SRC_DIR/project.godot"

line_count=$(wc -l < "$OUTPUT_FILE")
size=$(du -h "$OUTPUT_FILE" | cut -f1)
echo "Done — $line_count lines, $size written to $OUTPUT_FILE"
