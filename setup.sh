#!/bin/bash
# dualboot - install everything the Mac needs (safe to run again).
#   Xcode Command Line Tools, Homebrew packages (libimobiledevice, libirecovery, ldid, libusb, ipsw)
#   and a private Python environment ./.venv (pyimg4, pyusb, pymobiledevice3).
cd "$(dirname "$0")" || exit 1
G=$'\033[1;32m'; Y=$'\033[1;33m'; R=$'\033[1;31m'; C=$'\033[1;36m'; N=$'\033[0m'
step() { echo "${C}==>${N} $*"; }
fail() { echo "${R}✗ $*${N}"; exit 1; }

[ "$(uname)" = "Darwin" ] || fail "macOS only"

step "Xcode Command Line Tools"
if ! xcode-select -p >/dev/null 2>&1; then
    xcode-select --install
    fail "the Command Line Tools installer is opening - run ./setup.sh again when it has finished"
fi

step "Homebrew"
if ! command -v brew >/dev/null 2>&1; then
    for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do [ -x "$b" ] && eval "$("$b" shellenv)"; done
fi
command -v brew >/dev/null 2>&1 || fail "Homebrew is missing - install it from https://brew.sh, then run ./setup.sh again"

step "Homebrew packages"
# formula:command - skipped when the command already exists (keeps a custom irecovery/ldid build untouched)
for fc in libimobiledevice:iproxy libimobiledevice:idevice_id libirecovery:irecovery ldid:ldid python@3:python3; do
    f=${fc%%:*}; c=${fc##*:}
    if command -v "$c" >/dev/null 2>&1; then echo "   ${G}✓${N} $c ($(command -v "$c"))"
    else brew install "$f" || fail "brew install $f"; fi
done
brew list --versions libusb >/dev/null 2>&1 || brew install libusb || fail "brew install libusb"
echo "   ${G}✓${N} libusb"
# blacktop/ipsw: IPSW download, remote extraction of single components (pre-check), rootfs DMG decryption
IPSW_MIN=3.1.700
command -v ipsw >/dev/null 2>&1 || brew install blacktop/tap/ipsw || fail "brew install blacktop/tap/ipsw"
iv=$(ipsw version 2>/dev/null | sed -n 's/^Version: *\([0-9.]*\).*/\1/p')
if [ "$(printf '%s\n%s\n' "$IPSW_MIN" "$iv" | sort -V | head -1)" != "$IPSW_MIN" ]; then
    brew upgrade blacktop/tap/ipsw || fail "ipsw $iv is older than $IPSW_MIN: brew upgrade blacktop/tap/ipsw"
    iv=$(ipsw version 2>/dev/null | sed -n 's/^Version: *\([0-9.]*\).*/\1/p')
fi
echo "   ${G}✓${N} ipsw $iv"

step "Python environment (.venv)"
PYB=$(brew --prefix)/bin/python3
[ -x "$PYB" ] || PYB=$(command -v python3)
[ -d .venv ] || "$PYB" -m venv .venv || fail "could not create .venv"
.venv/bin/python3 -m pip install -q --upgrade pip
.venv/bin/python3 -m pip install -q -r requirements.txt || fail "pip install -r requirements.txt"
echo "   ${G}✓${N} $(.venv/bin/python3 --version) + $(tr '\n' ' ' < requirements.txt)"

chmod +x dualboot.sh boot.sh dualboot.py tools/usbliter8ctl 2>/dev/null
step "Check"
.venv/bin/python3 dualboot.py doctor && echo "${G}Done. Run ./dualboot.sh to open the menu.${N}"
