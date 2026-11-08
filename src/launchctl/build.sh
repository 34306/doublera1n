#!/usr/bin/env bash
# launchctl for iOS 27: the Procursus launchctl from payload/boot/bootstrap.tar.gz imports _launch_active_user_switch
# strongly, a libSystem routine iOS 26+ no longer has, so dyld refuses to load it. Mark that import weak (the call is
# already guarded at runtime) and re-sign with the original identifier and entitlements.
#   src/launchctl/build.sh [out]      (default: payload/boot/launchctl)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-$HERE/../../payload/boot/launchctl}"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
tar -xzf "$HERE/../../payload/boot/bootstrap.tar.gz" -C "$TMP" ./var/jb/usr/bin/launchctl
ORIG="$TMP/var/jb/usr/bin/launchctl"
ldid -e "$ORIG" > "$TMP/ents.plist"
ID=$(codesign -dvvv "$ORIG" 2>&1 | sed -n 's/^Identifier=//p')
python3 "$HERE/weakimport.py" "$ORIG" "$TMP/launchctl" _launch_active_user_switch
ldid -S"$TMP/ents.plist" -I"$ID" "$TMP/launchctl"
cp "$TMP/launchctl" "$OUT"; chmod 755 "$OUT"
echo "launchctl -> $OUT ($(codesign -dvvv "$OUT" 2>&1 | sed -n 's/^CDHash=//p'))"
