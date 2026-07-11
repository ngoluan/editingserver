#!/bin/bash
cd '/Users/seconduser/StudioProjects/WindowWeb'
echo "Running opencode to implement the patch..."
opencode run "Implement the patch file at '/Users/seconduser/StudioProjects/WindowWeb/.windowedwebbrowser_patch.txt' in this project. Read the patch file and apply the changes described in it."
echo ""
echo "--- opencode finished ---"
echo "Press Enter to close this window."
read
rm -f '/Users/seconduser/StudioProjects/WindowWeb/.windowedwebbrowser_patch.txt'
