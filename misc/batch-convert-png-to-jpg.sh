#!/bin/bash
#
# batch-convert-png-to-jpg.sh
#
# Purpose:
#   Recursively finds all .png files under the current directory, converts
#   each to a .jpg using ImageMagick, and removes the original .png once
#   the conversion succeeds. Useful for shrinking screenshot/image archives
#   where PNG's lossless size isn't needed.
#
# Usage:
#   ./batch-convert-png-to-jpg.sh [quality]
#
#   quality   Optional. JPEG quality 1-100 (default: 25). Lower = smaller
#             file size, more compression artifacts.
#
# Requirements:
#   - ImageMagick's `convert` command available on PATH.
#   - Run from the directory you want to scan; it recurses into subfolders.
#
# Warning:
#   This DELETES the source .png after a successful conversion. There is no
#   undo. Test on a copy of your data first, or comment out the `rm` line
#   if you want to keep the originals.

set -euo pipefail

QUALITY="${1:-25}"

find . -name "*.png" -type f -exec bash -c '
    quality="$1"
    shift
    for img; do
        convert "$img" -quality "$quality" "${img%.png}.jpg"
        rm "$img"
    done
' bash "$QUALITY" {} +
