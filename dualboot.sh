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

cleanup() { tput cnorm 2>/dev/null; stty echo 2>/dev/null; }
trap cleanup EXIT
trap 'cleanup; echo; exit 130' INT

device_line() {
    local q mode ecid pwnd
    q=$(irecovery -q 2>/dev/null)
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

header() {
    clear
    echo "${C_TITLE}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo "${C_TITLE}║    dualboot · 2nd Data · iPhone 11 / 11 Pro / 11 Pro Max     ║${C_RESET}"
    echo "${C_TITLE}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo "  $(device_line)"
    echo "  $(version_line)"
    echo "  ${C_DIM}A normal reboot = stock iOS. 2nd Data: pwned DFU → Boot 2nd Data${C_RESET}"
    echo
}

version_line() {
    local f="${DUALBOOT_HOME:-$HOME/dualboot-work}/selected-version.json" v b
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
        [ -n "$p" ] && run_cmd select --ipsw "${p/#\~/$HOME}" --prepare
    fi
}

# menu "title" opt1 opt2 ...  -> sets MENU_INDEX (0-based)
menu() {
    local title="$1"; shift
    local n=$# cur=0 key i
    local -a opts=("$@")
    tput civis 2>/dev/null
    while true; do
        header
        echo "  ${C_BOLD}$title${C_RESET}   ${C_DIM}(↑/↓ select, Enter run, q quit)${C_RESET}"
        echo
        for ((i = 0; i < n; i++)); do
            if [ $i -eq $cur ]; then echo "   ${C_SEL} ▶ ${opts[$i]} ${C_RESET}"
            else echo "     ${opts[$i]}"; fi
        done
        IFS= read -rsn1 key
        if [ "$key" = $'\033' ]; then
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
    tput cnorm 2>/dev/null
    MENU_INDEX=$cur
}

confirm() {   # confirm "question" -> 0 if yes
    menu "$1" "No" "Yes, continue"
    [ "$MENU_INDEX" -eq 1 ]
}

pause() { echo; read -rsp "  ${C_DIM}Press Enter to return to the menu...${C_RESET}" _; }

run_cmd() {
    header
    echo "  ${C_BOLD}▶ $*${C_RESET}"; echo
    "$PY" dualboot.py "$@"
    local rc=$?
    echo
    if [ $rc -eq 0 ]; then echo "  ${C_OK}✓ done${C_RESET}"; else echo "  ${C_ERR}✗ failed (exit $rc)${C_RESET}"; fi
    pause
}

while true; do
    menu "Choose an action" \
        "Boot 2nd Data             (phone in pwned DFU)" \
        "Select iOS version        (the one installed)" \
        "Install 2nd Data          (creates the DataB volume)" \
        "Re-apply fixes            (2nd Data running)" \
        "SSH into 2nd Data" \
        "Status / check the Mac" \
        "Install requirements      (setup.sh, first use)" \
        "Remove 2nd Data           (deletes DataB, back to stock only)" \
        "Quit"
    case $MENU_INDEX in
        0) run_cmd boot ;;
        1) choose_version ;;
        2) if confirm "Install 2nd Data? (phone in pwned DFU; only ADDS the DataB volume, stock iOS is not touched)"; then
               run_cmd install; fi ;;
        3) run_cmd provision ;;
        4) header; "$PY" dualboot.py ssh; pause ;;
        5) header; "$PY" dualboot.py status; echo; "$PY" dualboot.py versions; echo; "$PY" dualboot.py doctor; pause ;;
        6) header; ./setup.sh; pause ;;
        7) if confirm "REMOVE 2nd Data? Everything in DataB (apps, accounts, jailbreak) is lost. Stock iOS is kept."; then
               if confirm "Really delete DataB?"; then run_cmd remove; fi; fi ;;
        8) clear; exit 0 ;;
    esac
done
