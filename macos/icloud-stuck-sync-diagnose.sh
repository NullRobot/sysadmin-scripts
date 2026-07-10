#!/usr/bin/env bash
#
# icloud-stuck-sync-diagnose.sh
#
# Purpose:
#   Diagnoses a stuck macOS iCloud Drive sync and reports on local disk
#   space usage so you can figure out why iCloud Drive won't finish
#   syncing (usually: not enough free local disk space).
#
# What it does:
#   1. Restarts the iCloud sync daemons (bird, fileproviderd, cloudd).
#      These respawn automatically within a few seconds; killing them
#      just clears any stuck internal state.
#   2. Reports how many files are still waiting to download from iCloud
#      (.icloud placeholder stubs) and prints brctl status if available.
#   3. Checks a target folder (see --target below) for extended
#      attributes and leftover sync temp files that can indicate a
#      stuck sync.
#   4. Prints overall disk usage and the top space consumers in your
#      home directory.
#   5. Reports purgeable/cache space you could reclaim (Caches, Xcode
#      DerivedData, Docker, Trash).
#   6. Breaks down the target folder's contents by subdirectory size
#      and file type.
#   7. Prints plain-language recommendations for freeing space or
#      working around a full disk.
#
# Usage:
#   ./icloud-stuck-sync-diagnose.sh [target_folder_name]
#
#   target_folder_name   Optional. Name of a folder under $HOME you want
#                         analyzed specifically (e.g. a large project or
#                         data folder that isn't syncing). Defaults to
#                         "BigFolder" if not given -- edit TARGET_DIR
#                         below or pass an argument to point it at your
#                         own folder.
#
# Requirements:
#   macOS with iCloud Drive enabled. No admin/root required. Uses only
#   built-in tools (killall, find, du, df, xattr) plus brctl if present.
#
# Notes:
#   This is read-only / diagnostic except for restarting the sync
#   daemons in step 1 (safe, they auto-restart) and the two commented
#   example cleanup commands printed at the end, which are NOT run
#   automatically -- copy/paste them yourself after reviewing what
#   they'll delete.

set -euo pipefail

# Folder under $HOME to analyze in steps 3 and 6. Override via first
# argument, e.g.: ./icloud-stuck-sync-diagnose.sh Projects
TARGET_DIR_NAME="${1:-BigFolder}"
TARGET_DIR="$HOME/$TARGET_DIR_NAME"

echo "=== iCloud Stuck Sync Fix + Disk Analysis ==="
echo "Time: $(date)"
echo

# --- 1. Stop iCloud sync processes (they'll restart automatically) ---
echo "## 1) Stopping iCloud sync processes..."
# These will restart automatically within seconds, but it clears stuck state
killall bird 2>/dev/null && echo "  Killed: bird" || echo "  bird: not running"
killall fileproviderd 2>/dev/null && echo "  Killed: fileproviderd" || echo "  fileproviderd: not running"
killall cloudd 2>/dev/null && echo "  Killed: cloudd (user instance)" || echo "  cloudd: not running or protected"
echo
sleep 2

# --- 2. Check for pending iCloud operations ---
echo "## 2) Checking for pending iCloud sync operations..."
ICLOUD_ROOT="$HOME/Library/Mobile Documents/com~apple~CloudDocs"

# Look for .icloud placeholder files (files waiting to download)
echo "Files waiting to download from iCloud (.icloud stubs):"
find "$ICLOUD_ROOT" -name "*.icloud" 2>/dev/null | wc -l | xargs echo "  Count:"
echo

# Check for pending uploads using brctl (if available)
if command -v brctl &>/dev/null; then
    echo "iCloud Drive status via brctl:"
    brctl status 2>/dev/null | head -20 || echo "  (brctl not providing useful output)"
    echo
fi

# --- 3. Check extended attributes on the target folder that might indicate stuck sync ---
echo "## 3) Checking $TARGET_DIR_NAME for iCloud sync markers..."
if [[ -d "$TARGET_DIR" ]]; then
    echo "Extended attributes on $TARGET_DIR_NAME:"
    xattr -l "$TARGET_DIR" 2>/dev/null || echo "  (none)"
    echo

    # Check if there's a copy in progress indicator
    echo "Looking for .DS_Store and sync temp files..."
    find "$TARGET_DIR" -name ".com.apple.*" -o -name "._*" 2>/dev/null | head -10 || true
else
    echo "  $TARGET_DIR_NAME does not exist under \$HOME (pass a folder name as the first argument)"
fi
echo

# --- 4. Disk space analysis ---
echo "## 4) Disk Space Analysis (this is usually the real problem)"
echo
echo "Overall disk usage:"
df -h "$HOME" | tail -1
echo

echo "Top 10 space consumers in your home directory:"
du -sh "$HOME"/* "$HOME"/.[!.]* 2>/dev/null | sort -hr | head -15
echo

echo "iCloud Drive local size:"
du -sh "$ICLOUD_ROOT" 2>/dev/null || echo "  Could not measure"
echo

# Check if other cloud sync clients are taking space
echo "Checking for other cloud sync folders..."
for d in "Proton Drive" "ProtonDrive" "Google Drive" "GoogleDrive" "Dropbox" "OneDrive"; do
    if [[ -d "$HOME/$d" ]]; then
        du -sh "$HOME/$d" 2>/dev/null
    fi
done
echo

# --- 5. Cache and purgeable space ---
echo "## 5) Purgeable/cache space you could reclaim:"
echo

# Library caches
echo "Library/Caches size:"
du -sh "$HOME/Library/Caches" 2>/dev/null || echo "  N/A"

# Xcode derived data (if you're a developer)
if [[ -d "$HOME/Library/Developer/Xcode/DerivedData" ]]; then
    echo "Xcode DerivedData:"
    du -sh "$HOME/Library/Developer/Xcode/DerivedData"
fi

# Docker (if present)
if [[ -d "$HOME/Library/Containers/com.docker.docker" ]]; then
    echo "Docker:"
    du -sh "$HOME/Library/Containers/com.docker.docker"
fi

# Trash
echo "Trash:"
du -sh "$HOME/.Trash" 2>/dev/null || echo "  Empty or inaccessible"
echo

# --- 6. Specific target folder analysis ---
echo "## 6) $TARGET_DIR_NAME breakdown (what's inside?)"
if [[ -d "$TARGET_DIR" ]]; then
    echo "Subdirectory sizes (top 10):"
    du -sh "$TARGET_DIR"/* 2>/dev/null | sort -hr | head -10
    echo
    echo "File type breakdown (approximate):"
    find "$TARGET_DIR" -type f 2>/dev/null | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -10
fi
echo

# --- 7. Recommendations ---
echo "## 7) RECOMMENDATIONS"
echo
echo "If your disk is near full, iCloud Drive can't finish syncing large"
echo "folders until you free up space. Options:"
echo
echo "  A) FREE UP SPACE FIRST (recommended):"
echo "     - Empty Trash: rm -rf ~/.Trash/*"
echo "     - Clear caches: rm -rf ~/Library/Caches/*"
echo "     - Review large files above"
echo
echo "  B) USE AN EXTERNAL DRIVE for $TARGET_DIR_NAME temporarily"
echo "     - Move $TARGET_DIR_NAME to an external drive"
echo "     - Frees up local space instantly"
echo "     - Then decide on a longer-term cloud strategy"
echo
echo "  C) UPLOAD DIRECTLY to cloud storage (bypassing the local iCloud folder)"
echo "     - Use a tool like rclone to upload $TARGET_DIR_NAME directly to iCloud/Proton/Google"
echo "     - Doesn't require local disk space"
echo
echo "Example command to empty Trash (review contents before running):"
echo "  rm -rf ~/.Trash/*"
echo
echo "After freeing space, rerun this script to verify."
