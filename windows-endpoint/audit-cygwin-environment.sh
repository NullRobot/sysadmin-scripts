#!/bin/bash
# ============================================================================
# audit-cygwin-environment.sh
#
# PURPOSE
#   Captures a snapshot of a Cygwin installation's configuration so it can be
#   reviewed or replicated on a new machine (e.g. before a PC migration or
#   rebuild). Collects Cygwin version/package info, dotfiles, SSH client/server
#   config, cron jobs, installed CLI tools, terminal multiplexer config,
#   mounted filesystems, a home directory tree, Python/pip state, local git
#   repos, and X11 config.
#
# USAGE
#   ./audit-cygwin-environment.sh [output_dir]
#
#   output_dir   Optional. Directory (Cygwin path) to write report files to.
#                Defaults to /cygdrive/c/temp/pc-audit/cygwin
#
# REQUIREMENTS
#   - Run from a Cygwin bash shell on the target Windows machine.
#   - Standard Cygwin userland (cygcheck, cygrunsrv, awk, find) available on
#     PATH. Missing optional tools are skipped gracefully.
#   - No admin/elevated rights required; the script only reads config and
#     writes to the chosen output directory.
#
# OUTPUT
#   Writes numbered .txt report files (01-cygwin-base.txt ... 13-x11.txt) into
#   the output directory, one per audit section.
#
# NOTES
#   - This script reads and copies SSH client config and any authorized_keys
#     file verbatim into its output. Public keys are not secret, but treat
#     the resulting output directory as sensitive (it also captures hostnames
#     and usernames from local config) and store/transfer it accordingly.
#     It does NOT read or copy private key material.
#   - Adjust the tool list in section 7 to match what you care about
#     auditing in your own environment.
# ============================================================================

OUT="${1:-/cygdrive/c/temp/pc-audit/cygwin}"
mkdir -p "$OUT"

echo "=== CYGWIN AUDIT STARTING ==="

# ──────────────────────────────────────────────────
# 1. CYGWIN VERSION AND BASE INFO
# ──────────────────────────────────────────────────
echo "  [*] Cygwin base info..."
{
    echo "=== CYGWIN VERSION ==="
    uname -a
    echo ""
    echo "=== CYGWIN INSTALL ROOT ==="
    cygpath -w /
    echo ""
    echo "=== SHELL ==="
    echo "$SHELL"
    echo ""
    echo "=== HOME ==="
    echo "$HOME"
    echo ""
    echo "=== PATH ==="
    echo "$PATH" | tr ':' '\n'
} > "$OUT/01-cygwin-base.txt" 2>&1

# ──────────────────────────────────────────────────
# 2. ALL INSTALLED CYGWIN PACKAGES (full list with versions)
# ──────────────────────────────────────────────────
echo "  [*] Cygwin packages..."
{
    echo "=== INSTALLED PACKAGES (from cygcheck) ==="
    cygcheck -c -d 2>/dev/null || echo "(cygcheck not available)"
    echo ""
    echo "=== PACKAGE COUNT ==="
    cygcheck -c -d 2>/dev/null | tail -n +3 | wc -l
} > "$OUT/02-cygwin-packages-full.txt" 2>&1

# Also save just package names for easy comparison
cygcheck -c -d 2>/dev/null | tail -n +3 | awk '{print $1}' | sort > "$OUT/02b-cygwin-package-names.txt" 2>&1

# ──────────────────────────────────────────────────
# 3. DOT FILES (full content for important ones)
# ──────────────────────────────────────────────────
echo "  [*] Dot files..."
{
    for f in ~/.bashrc ~/.bash_profile ~/.profile ~/.bash_aliases ~/.inputrc ~/.vimrc ~/.tmux.conf ~/.screenrc ~/.gitconfig ~/.minttyrc ~/.startxwinrc ~/.Xresources ~/.Xdefaults; do
        if [ -f "$f" ]; then
            echo "=========================================="
            echo "=== $(basename $f) ==="
            echo "=========================================="
            cat "$f"
            echo ""
            echo ""
        fi
    done
} > "$OUT/03-dotfiles.txt" 2>&1

# ──────────────────────────────────────────────────
# 4. SSH CONFIGURATION (client + server)
# ──────────────────────────────────────────────────
echo "  [*] SSH configuration..."
{
    echo "=== SSH CLIENT CONFIG ==="
    if [ -f ~/.ssh/config ]; then
        cat ~/.ssh/config
    else
        echo "(no ~/.ssh/config)"
    fi

    echo ""
    echo "=== AUTHORIZED KEYS ==="
    if [ -f ~/.ssh/authorized_keys ]; then
        cat ~/.ssh/authorized_keys
    else
        echo "(no authorized_keys)"
    fi

    echo ""
    echo "=== SSH KEY FILES ==="
    ls -la ~/.ssh/ 2>/dev/null || echo "(no .ssh directory)"

    echo ""
    echo "=== SSHD CONFIG (user custom) ==="
    if [ -f ~/sshd_config ]; then
        cat ~/sshd_config
    else
        echo "(no ~/sshd_config)"
    fi

    echo ""
    echo "=== SSHD CONFIG (system) ==="
    if [ -f /etc/sshd_config ]; then
        cat /etc/sshd_config
    elif [ -f /etc/ssh/sshd_config ]; then
        cat /etc/ssh/sshd_config
    else
        echo "(no system sshd_config found)"
    fi

    echo ""
    echo "=== SSHD HOST KEYS ==="
    ls -la /etc/ssh/ssh_host_* 2>/dev/null || echo "(no host keys in /etc/ssh/)"
    ls -la ~/ssh_host_* 2>/dev/null || echo "(no host keys in ~/)"

    echo ""
    echo "=== SSHD PROCESS ==="
    ps -ef | grep sshd | grep -v grep

    echo ""
    echo "=== SSHD SERVICE (cygrunsrv) ==="
    cygrunsrv -Q sshd 2>/dev/null || echo "(cygrunsrv not available or sshd not registered)"

    echo ""
    echo "=== CYGWIN SSHD STARTUP ==="
    # Check for any startup shortcuts or scripts
    ls -la ~/sshd_start* 2>/dev/null
    ls -la ~/start_sshd* 2>/dev/null
    # Check Windows startup folder
    ls -la "/cygdrive/c/Users/$USER/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"*.* 2>/dev/null
} > "$OUT/04-ssh-config.txt" 2>&1

# ──────────────────────────────────────────────────
# 5. CYGWIN /etc/ CONFIGURATION FILES
# ──────────────────────────────────────────────────
echo "  [*] Cygwin /etc/ configs..."
{
    for f in /etc/passwd /etc/group /etc/fstab /etc/nsswitch.conf /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/skel/.bashrc /etc/skel/.bash_profile /etc/hosts /etc/resolv.conf; do
        if [ -f "$f" ]; then
            echo "=========================================="
            echo "=== $f ==="
            echo "=========================================="
            cat "$f"
            echo ""
        fi
    done
} > "$OUT/05-etc-configs.txt" 2>&1

# ──────────────────────────────────────────────────
# 6. CRON / SCHEDULED JOBS
# ──────────────────────────────────────────────────
echo "  [*] Cron jobs..."
{
    echo "=== USER CRONTAB ==="
    crontab -l 2>/dev/null || echo "(no crontab)"

    echo ""
    echo "=== CRON SERVICE STATUS ==="
    cygrunsrv -Q cron 2>/dev/null || echo "(cron service not registered)"

    echo ""
    echo "=== /etc/crontab ==="
    cat /etc/crontab 2>/dev/null || echo "(no /etc/crontab)"

    echo ""
    echo "=== /etc/cron.d/ ==="
    ls -la /etc/cron.d/ 2>/dev/null || echo "(no /etc/cron.d/)"
} > "$OUT/06-cron.txt" 2>&1

# ──────────────────────────────────────────────────
# 7. INSTALLED BINARY TOOLS (what's in /usr/bin, /usr/local/bin)
# ──────────────────────────────────────────────────
echo "  [*] Binary tools inventory..."
{
    echo "=== KEY TOOLS VERSION CHECK ==="
    for cmd in bash zsh tmux screen vim nano git curl wget rsync ssh scp sftp openssl python python3 pip pip3 node npm gcc g++ make cmake perl ruby java javac php go rustc cargo sqlite3 jq yq xmlstarlet nc socat nmap ncat netcat tcpdump wireshark tshark htop iftop iotop strace ltrace gdb valgrind diff3 patch dos2unix unix2dos iconv tree zip unzip tar gzip bzip2 xz 7z rar p7zip lynx links w3m mutt gpg gpg2 rdiff-backup duplicity ansible terraform; do
        if command -v "$cmd" &>/dev/null; then
            ver=$($cmd --version 2>&1 | head -1)
            printf "  %-20s %s\n" "$cmd" "$ver"
        fi
    done

    echo ""
    echo "=== ALL EXECUTABLES IN /usr/local/bin ==="
    ls -la /usr/local/bin/ 2>/dev/null || echo "(empty or doesn't exist)"

    echo ""
    echo "=== CUSTOM SCRIPTS IN ~/bin ==="
    ls -la ~/bin/ 2>/dev/null || echo "(no ~/bin)"
} > "$OUT/07-tools.txt" 2>&1

# ──────────────────────────────────────────────────
# 8. TMUX / BYOBU / SCREEN CONFIG
# ──────────────────────────────────────────────────
echo "  [*] Terminal multiplexer config..."
{
    echo "=== TMUX CONFIG ==="
    if [ -f ~/.tmux.conf ]; then
        cat ~/.tmux.conf
    else
        echo "(no ~/.tmux.conf)"
    fi

    echo ""
    echo "=== BYOBU CONFIG ==="
    if [ -d ~/.byobu ]; then
        ls -la ~/.byobu/
        echo ""
        for f in ~/.byobu/*; do
            if [ -f "$f" ]; then
                echo "--- $(basename $f) ---"
                cat "$f"
                echo ""
            fi
        done
    else
        echo "(no ~/.byobu)"
    fi

    echo ""
    echo "=== SCREEN CONFIG ==="
    if [ -f ~/.screenrc ]; then
        cat ~/.screenrc
    else
        echo "(no ~/.screenrc)"
    fi
} > "$OUT/08-multiplexer.txt" 2>&1

# ──────────────────────────────────────────────────
# 9. MOUNTED FILESYSTEMS / FSTAB
# ──────────────────────────────────────────────────
echo "  [*] Mount points..."
{
    echo "=== MOUNT ==="
    mount

    echo ""
    echo "=== DF ==="
    df -h

    echo ""
    echo "=== FSTAB ==="
    cat /etc/fstab 2>/dev/null
} > "$OUT/09-mounts.txt" 2>&1

# ──────────────────────────────────────────────────
# 10. HOME DIRECTORY FULL LISTING
# ──────────────────────────────────────────────────
echo "  [*] Home directory tree..."
{
    echo "=== HOME DIRECTORY (2 levels deep) ==="
    find ~ -maxdepth 2 -not -path '*/\.*' 2>/dev/null | head -200

    echo ""
    echo "=== HIDDEN FILES/DIRS IN HOME ==="
    ls -la ~/ 2>/dev/null

    echo ""
    echo "=== DISK USAGE OF HOME SUBDIRS ==="
    du -sh ~/*/ 2>/dev/null | sort -rh | head -20
} > "$OUT/10-home-tree.txt" 2>&1

# ──────────────────────────────────────────────────
# 11. PYTHON / PIP IN CYGWIN CONTEXT
# ──────────────────────────────────────────────────
echo "  [*] Python in Cygwin..."
{
    echo "=== PYTHON VERSIONS ==="
    which python 2>/dev/null && python --version 2>&1
    which python3 2>/dev/null && python3 --version 2>&1
    which python3.11 2>/dev/null && python3.11 --version 2>&1
    which python3.12 2>/dev/null && python3.12 --version 2>&1

    echo ""
    echo "=== PIP PACKAGES ==="
    pip list 2>/dev/null || pip3 list 2>/dev/null || echo "(pip not available)"

    echo ""
    echo "=== VIRTUALENVS ==="
    ls -la ~/.virtualenvs/ 2>/dev/null || echo "(no .virtualenvs)"
    ls -la ~/venv*/ 2>/dev/null || echo "(no venv in home)"
} > "$OUT/11-python-cygwin.txt" 2>&1

# ──────────────────────────────────────────────────
# 12. GIT REPOS IN HOME
# ──────────────────────────────────────────────────
echo "  [*] Git repos..."
{
    echo "=== GIT REPOS UNDER HOME ==="
    find ~ -maxdepth 3 -name ".git" -type d 2>/dev/null | while read gitdir; do
        repo=$(dirname "$gitdir")
        echo "  $repo"
        (cd "$repo" && echo "    Branch: $(git branch --show-current 2>/dev/null)" && echo "    Remote: $(git remote -v 2>/dev/null | head -1)")
        echo ""
    done
} > "$OUT/12-git-repos.txt" 2>&1

# ──────────────────────────────────────────────────
# 13. X11 / GUI CONFIG (if using Cygwin/X)
# ──────────────────────────────────────────────────
echo "  [*] X11 config..."
{
    echo "=== X11 INSTALLED ==="
    cygcheck -c -d 2>/dev/null | grep -i xorg
    cygcheck -c -d 2>/dev/null | grep -i xinit
    cygcheck -c -d 2>/dev/null | grep -i xserver

    echo ""
    echo "=== DISPLAY VARIABLE ==="
    echo "$DISPLAY"

    echo ""
    echo "=== .Xresources ==="
    cat ~/.Xresources 2>/dev/null || echo "(none)"

    echo ""
    echo "=== .startxwinrc ==="
    cat ~/.startxwinrc 2>/dev/null || echo "(none)"
} > "$OUT/13-x11.txt" 2>&1

echo ""
echo "=== CYGWIN AUDIT COMPLETE ==="
echo "Output: $OUT"
ls -la "$OUT"
