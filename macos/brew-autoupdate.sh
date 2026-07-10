#!/bin/bash
#
# brew-autoupdate.sh
#
# Purpose:
#   Updates Homebrew's package index and upgrades all installed formulae/casks.
#   Prints timestamped banners so output is easy to scan in a log file.
#
# Usage:
#   ./brew-autoupdate.sh
#
#   Intended to be run on a schedule (cron or launchd) to keep Homebrew
#   packages current. Example launchd/cron invocation:
#     0 9 * * * /path/to/brew-autoupdate.sh >> /path/to/brew-autoupdate.log 2>&1
#
# Requirements:
#   - Homebrew installed at a standard location (/opt/homebrew or /usr/local)
#   - bash
#
# Notes:
#   - set -u causes the script to exit on use of an unset variable.
#   - PATH is set explicitly since scheduled jobs (cron/launchd) often run
#     with a minimal environment that doesn't include Homebrew's bin dirs.

set -u
export PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

echo ""
echo "=== brew autoupdate $(date '+%Y-%m-%d %H:%M:%S %Z') ==="
brew update
echo ""
brew upgrade
echo "=== done $(date '+%H:%M:%S') ==="
