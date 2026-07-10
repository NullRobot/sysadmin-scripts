#!/bin/bash
#
# macos-safe-erase-usb.sh
#
# Purpose:
#   Safely erase and format a small USB flash drive as exFAT/MBR on macOS,
#   with hard guardrails to prevent accidentally wiping the internal disk
#   or any large external drive (backup drives, Time Machine volumes, etc).
#
# Usage:
#   bash macos-safe-erase-usb.sh <diskN>
#
#   Example:
#     bash macos-safe-erase-usb.sh disk15
#
#   Find the right disk identifier first with:
#     diskutil list
#
# Requirements:
#   - macOS with the built-in `diskutil` command.
#   - If a third-party filesystem mounting tool (e.g. one used to mount
#     Linux-formatted volumes) has the target device mounted, unmount it
#     with that tool BEFORE running this script, or the erase may fail.
#   - Run as your normal user first; only add `sudo` if diskutil reports
#     a permission error.
#
# Safety guardrails (built in, cannot be bypassed via arguments):
#   - Refuses to touch any disk marked "Internal".
#   - Refuses any disk larger than 256GB (adjust the SIZE_LIMIT_BYTES
#     variable below if you need a different ceiling).
#   - Warns (but does not block) if the reported media name doesn't
#     contain your expected brand string, so you can double check before
#     confirming.
#   - Requires you to type ERASE at an interactive prompt before doing
#     anything destructive.
#
# Notes:
#   - Adjust EXPECTED_BRAND below to match your own flash drive, or
#     remove that check entirely if you don't want it.
#   - The final volume is labeled per the VOLUME_NAME variable below.

set -u

DISK="${1:-}"
if [ -z "$DISK" ]; then
    echo "Usage: bash $0 <diskN>   (e.g. disk15; run 'diskutil list' to find it)"
    exit 1
fi
DEV="/dev/$DISK"
DU=/usr/sbin/diskutil

# Tune these for your environment
SIZE_LIMIT_BYTES=274877906944   # 256GB
EXPECTED_BRAND="SanDisk"        # set to "" to skip the brand check
VOLUME_NAME="USBDRIVE"

info() { $DU info "$DEV" 2>/dev/null; }
[ -n "$(info)" ] || { echo "No such disk: $DEV"; echo "Run '$DU list' and pass the right one, e.g. bash $0 disk15"; exit 1; }

NAME=$(info | awk -F: '/Device \/ Media Name/{print $2}' | sed 's/^[[:space:]]*//')
REMOV=$(info | awk -F: '/Removable Media/{print $2}' | sed 's/^[[:space:]]*//')
INTERNAL=$(info | awk -F: '/^[[:space:]]*Internal:/{print $2}' | sed 's/^[[:space:]]*//')
SIZE=$(info | awk -F'[()]' '/Disk Size/{print $2}' | awk '{print $1}')

echo "target    : $DEV"
echo "media name: $NAME"
echo "size bytes: $SIZE"
echo "removable=$REMOV internal=$INTERNAL"
echo

# hard safety guards
[ "$INTERNAL" = "Yes" ] && { echo "REFUSING: $DEV is the internal disk."; exit 1; }
if [ -n "$SIZE" ] && [ "$SIZE" -gt "$SIZE_LIMIT_BYTES" ]; then
    echo "REFUSING: $DEV is larger than the configured limit ($SIZE_LIMIT_BYTES bytes). This is probably not the flash drive you meant to erase."
    exit 1
fi
if [ -n "$EXPECTED_BRAND" ]; then
    case "$NAME" in
        *"$EXPECTED_BRAND"*) ;;
        *) echo "NOTE: media name is '$NAME', expected to contain '$EXPECTED_BRAND'. Make sure this is really the right drive before continuing.";;
    esac
fi

read -r -p "Erase $DEV ($NAME) as exFAT/MBR? This destroys everything on it. Type ERASE to proceed: " ans
[ "$ans" = "ERASE" ] || { echo "Aborted, nothing changed."; exit 0; }

# If a third-party mounting tool has this device mounted, release it here
# before force-unmounting, e.g.:
#   your-mount-tool unmount 2>/dev/null || true
$DU unmountDisk force "$DEV" 2>/dev/null || true

echo "Erasing..."
if $DU eraseDisk ExFAT "$VOLUME_NAME" MBRFormat "$DEV"; then
    echo "OK - erased and formatted exFAT/MBR."
else
    echo "First attempt failed. Retrying with a fresh partition map..."
    $DU unmountDisk force "$DEV" 2>/dev/null || true
    if $DU partitionDisk "$DEV" 1 MBR ExFAT "$VOLUME_NAME" 100%; then
        echo "OK - formatted on the retry."
    else
        echo
        echo "Still failing. If you're using a third-party tool to mount"
        echo "non-native filesystems, make sure it has released the device,"
        echo "then run this script again."
        exit 1
    fi
fi

echo
echo "Result:"
info | grep -iE "Volume Name|File System|Mount Point|Content \(IOContent\)"
echo
echo "Next: copy your files onto it, e.g.:"
echo "  cp -R /path/to/source/. /Volumes/$VOLUME_NAME/"
