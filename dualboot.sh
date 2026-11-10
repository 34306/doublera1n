#!/bin/bash
# dualboot - menu (arrow keys + Enter). Works with the stock macOS bash 3.2.
cd "$(dirname "$0")" || exit 1
# first run (or a broken environment): ./setup.sh installs the Homebrew tools and creates .venv from requirements.txt
if ! [ -x .venv/bin/python3 ] || ! .venv/bin/python3 -c 'import importlib.util as u, sys; sys.exit(any(u.find_spec(m) is None for m in ("pyimg4", "usb", "pymobiledevice3")))' 2>/dev/null; then
    echo "First run: installing what the Mac needs (./setup.sh) ..."
    ./setup.sh || exit 1
fi
PY=.venv/bin/python3

C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
C_SEL=$'\033[1;30;46m'; C_TITLE=$'\033[1;36m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'; C_OK=$'\033[1;32m'

# The USB status line comes from a background poller while a menu waits for keys (a USB query can take seconds,
# far too slow for every key press). It is stopped before any action runs, so it never talks to the phone
# while a boot chain is being sent.
STATUS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/dualboot-menu.XXXXXX")
POLLER=
start_poller() {
    touch "$STATUS_DIR/run"
    (
        while [ -f "$STATUS_DIR/run" ]; do
            device_line > "$STATUS_DIR/dev.tmp" 2>/dev/null && mv -f "$STATUS_DIR/dev.tmp" "$STATUS_DIR/dev"
            for _ in 1 2 3 4 5 6 7 8 9 10; do [ -f "$STATUS_DIR/run" ] || break; sleep 0.2; done
        done
    ) &
    POLLER=$!
}
stop_poller() {
    rm -f "$STATUS_DIR/run"
    [ -n "$POLLER" ] && wait "$POLLER" 2>/dev/null
    POLLER=
}

cleanup() { stop_poller; rm -rf "$STATUS_DIR"; tput cnorm 2>/dev/null; stty echo 2>/dev/null; }
trap cleanup EXIT
trap 'cleanup; echo; exit 130' INT

# an Apple device (vendor 0x05ac) in DFU (0x1227) or Recovery (0x1280-0x1283) is on USB
usb_dfu_or_recovery() {
    ioreg -p IOUSB -l -w0 2>/dev/null | awk '
        /\+-o /          { v = ""; p = "" }
        /"idVendor" = /  { v = $NF }
        /"idProduct" = / { p = $NF }
        v == 1452 && (p == 4647 || (p >= 4736 && p <= 4739)) { f = 1 }
        END { exit !f }'
}

device_line() {
    local q mode ecid pwnd
    # irecovery -q waits ~6 s when nothing is in DFU/Recovery: ask the USB registry (instant) first
    if usb_dfu_or_recovery; then
        q=$(irecovery -q 2>/dev/null)
    fi
    if [ -n "$q" ]; then
        mode=$(echo "$q" | awk -F': ' '/^MODE/{print $2}')
        ecid=$(echo "$q" | awk -F': ' '/^ECID/{print $2}')
        pwnd=$(echo "$q" | awk -F': ' '/^PWND/{print $2}')
        if [ -n "$pwnd" ]; then echo "${C_OK}iPhone: $mode (pwned: $pwnd)  ECID $ecid${C_RESET}"
        else echo "${C_WARN}iPhone: $mode  ECID $ecid  (not pwned)${C_RESET}"; fi
        return
    fi
    local u; u=$(idevice_id -l 2>/dev/null | head -1)
    if [ -n "$u" ]; then echo "${C_OK}iPhone running iOS (USB): $u${C_RESET}"
    else echo "${C_DIM}No iPhone on USB${C_RESET}"; fi
}

# line "text": print and clear the rest of the terminal line (in-place redraws leave no leftovers)
line() { printf '%s\033[K\n' "$1"; }

# header         -> clear the screen, query the phone now (before an action)
# header redraw  -> repaint from the top without clearing, using the poller's last USB status (menus)
DEV_SHOWN=
header() {
    local dev
    if [ "$1" = redraw ]; then
        printf '\033[H'
        dev=$(cat "$STATUS_DIR/dev" 2>/dev/null)
        [ -n "$dev" ] || dev="${C_DIM}Checking USB ...${C_RESET}"
    else
        clear
        dev=$(device_line)
    fi
    DEV_SHOWN=$dev
    line "${C_TITLE}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    line "${C_TITLE}║ doublera1n · 2nd Data · A13: iPhone 11 series, SE 2, iPad 9  ║${C_RESET}"
    line "${C_TITLE}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    line "  $dev"
    line "  $(version_line)"
    line "  ${C_DIM}A normal reboot = stock iOS. 2nd Data: pwned DFU → Boot 2nd Data${C_RESET}"
    line ""
}

version_line() {
    local f="${DUALBOOT_HOME:-$PWD/dualboot-work}/selected-version.json" v b
    if [ -f "$f" ]; then
        v=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$f"); b=$(sed -n 's/.*"build": *"\([^"]*\)".*/\1/p' "$f")
        echo "${C_OK}iOS version: $v ($b)${C_RESET}"
    else
        echo "${C_WARN}iOS version: not selected (menu \"Select iOS version\")${C_RESET}"
    fi
}

# arrow-key list of iOS versions (local profiles + Apple builds) -> dualboot.py select
choose_version() {
    header; echo "  ${C_DIM}fetching the version list ...${C_RESET}"
    local -a builds labels
    local line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        builds+=("${line%%|*}"); labels+=("${line##*|}")
    done < <("$PY" dualboot.py versions --plain 2>/dev/null)
    labels+=("Detect from the iPhone running iOS (USB)" "From an IPSW file ..." "Back")
    menu "Select the iOS version INSTALLED on the iPhone (2nd Data must match it)" "${labels[@]}"
    local i=$MENU_INDEX n=${#builds[@]}
    if [ "$i" -lt "$n" ]; then run_cmd select --build "${builds[$i]}"
    elif [ "$i" -eq "$n" ]; then run_cmd select --auto
    elif [ "$i" -eq $((n + 1)) ]; then
        header; read -rp "  Path to the .ipsw: " p
        [ -n "$p" ] && run_cmd select --ipsw "${p/#\~/$HOME}"
    fi
}

# menu "title" opt1 opt2 ...  -> sets MENU_INDEX (0-based)
menu() {
    local title="$1"; shift
    local n=$# cur=0 key i
    local -a opts=("$@")
    tput civis 2>/dev/null
    start_poller
    clear
    while true; do
        header redraw
        line "  ${C_BOLD}$title${C_RESET}   ${C_DIM}(↑/↓ select, Enter run, q quit)${C_RESET}"
        line ""
        for ((i = 0; i < n; i++)); do
            if [ $i -eq $cur ]; then line "   ${C_SEL} ▶ ${opts[$i]} ${C_RESET}"
            else line "     ${opts[$i]}"; fi
        done
        printf '\033[J'
        # wait for a key; every second without one, repaint only if the USB status changed
        while ! IFS= read -rsn1 -t 1 key; do
            [ "$(cat "$STATUS_DIR/dev" 2>/dev/null)" != "$DEV_SHOWN" ] && { key=REDRAW; break; }
        done
        if [ "$key" = REDRAW ]; then
            continue
        elif [ "$key" = $'\033' ]; then
            read -rsn2 -t 1 key
            case "$key" in
                '[A') cur=$(( (cur - 1 + n) % n ));;
                '[B') cur=$(( (cur + 1) % n ));;
            esac
        elif [ -z "$key" ]; then
            break
        elif [ "$key" = "q" ] || [ "$key" = "Q" ]; then
            cur=$((n - 1)); break
        elif [[ "$key" =~ [1-9] ]] && [ "$key" -le "$n" ]; then
            cur=$((key - 1)); break
        fi
    done
    stop_poller
    tput cnorm 2>/dev/null
    MENU_INDEX=$cur
}

confirm() {   # confirm "question" -> 0 if yes
    menu "$1" "No" "Yes, continue"
    [ "$MENU_INDEX" -eq 1 ]
}

pause() { echo; read -rsp "  ${C_DIM}Press Enter to return to the menu...${C_RESET}" _; }

run_cmd() {   # run_cmd <dualboot.py args>; no args = Start (auto: install the first time, boot after)
    header
    if [ $# -eq 0 ]; then
        echo "  ${C_BOLD}▶ Start${C_RESET}: plug the iPhone in booted into iOS (its version is read), then put it into"
        echo "  pwned DFU when asked. The first time this installs 2nd Data (it asks for pwned DFU once more);"
        echo "  after that it just boots 2nd Data."
    else
        echo "  ${C_BOLD}▶ $*${C_RESET}"
    fi
    echo
    "$PY" dualboot.py "$@"
    local rc=$?
    echo
    if [ $rc -eq 0 ]; then echo "  ${C_OK}✓ done${C_RESET}"; else echo "  ${C_ERR}✗ failed (exit $rc)${C_RESET}"; fi
    pause
}

# 2nd iOS: another iOS 27.x on its own volumes (OS2System + OS2Data). DEVELOPING FEATURE - not device-tested yet.
os2_menu() {
    menu "Dualboot: 2nd iOS  [developing feature - not device-tested yet]" \
        "Install a 2nd iOS        (2nd Data must be running; ~22 GB on the phone)" \
        "Boot the 2nd iOS         (pwned DFU)" \
        "Re-apply fixes           (2nd iOS running)" \
        "Remove the 2nd iOS       (2nd Data must be running)" \
        "Status" \
        "Back"
    case $MENU_INDEX in
        0) os2_choose_build ;;
        1) run_cmd os2 boot ;;
        2) run_cmd os2 provision ;;
        3) if confirm "REMOVE the 2nd iOS? OS2System + OS2Data are deleted. Stock iOS and 2nd Data are kept."; then
               run_cmd os2 remove; fi ;;
        4) header; "$PY" dualboot.py os2 status; pause ;;
    esac
}

os2_choose_build() {
    header; echo "  ${C_DIM}fetching the version list ...${C_RESET}"
    local -a builds labels
    local line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        builds+=("${line%%|*}"); labels+=("${line##*|}")
    done < <("$PY" dualboot.py versions --plain 2>/dev/null)
    labels+=("From an IPSW file ..." "Back")
    menu "Which iOS for the 2nd iOS? (any iOS 27.x; it gets its own System + Data volumes)" "${labels[@]}"
    local i=$MENU_INDEX n=${#builds[@]}
    if [ "$i" -lt "$n" ]; then run_cmd os2 install --build "${builds[$i]}"
    elif [ "$i" -eq "$n" ]; then
        header; read -rp "  Path to the .ipsw: " p
        [ -n "$p" ] && run_cmd os2 install --ipsw "${p/#\~/$HOME}"
    fi
}

more_menu() {
    menu "More" \
        "Select iOS version        (Start reads it from the iPhone)" \
        "Status / check the Mac" \
        "Install requirements      (setup.sh)" \
        "Back"
    case $MENU_INDEX in
        0) choose_version ;;
        1) header; "$PY" dualboot.py status; echo; "$PY" dualboot.py versions; echo; "$PY" dualboot.py doctor; pause ;;
        2) header; ./setup.sh; pause ;;
    esac
}

while true; do
    menu "Choose an action" \
        "Start                     (installs 2nd Data the first time, boots it after)" \
        "SSH into 2nd Data" \
        "Re-apply fixes            (2nd Data running)" \
        "Remove 2nd Data           (deletes DataB, back to stock only)" \
        "Dualboot: 2nd iOS ...     [developing] another iOS 27.x on its own volumes" \
        "More ..." \
        "Quit"
    case $MENU_INDEX in
        0) run_cmd ;;
        1) header; "$PY" dualboot.py ssh; pause ;;
        2) run_cmd provision ;;
        3) if confirm "REMOVE 2nd Data? Everything in DataB (apps, accounts, jailbreak) is lost. Stock iOS is kept."; then
               if confirm "Really delete DataB?"; then run_cmd remove; fi; fi ;;
        4) os2_menu ;;
        5) more_menu ;;
        6) clear; exit 0 ;;
    esac
done
