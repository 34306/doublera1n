#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sdk=$(xcrun --sdk iphoneos --show-sdk-path)
relay_tmp=$(mktemp -d payload/setup/relay-build.XXXXXX)
trap 'rm -rf "$relay_tmp"' EXIT
xcrun clang -target arm64-apple-ios17.0 -isysroot "$sdk" -O2 -Wall -Wextra -Werror \
    src/rdsetup_usbrelay.c -framework CoreFoundation -framework IOKit \
    -o "$relay_tmp/rdsetup_usbrelay"
ldid -Ssrc/rdsetup_usbrelay.ents.plist "$relay_tmp/rdsetup_usbrelay"
codesign -dvvv "$relay_tmp/rdsetup_usbrelay"
mv "$relay_tmp/rdsetup_usbrelay" payload/setup/rdsetup_usbrelay
echo "Built and signed the USB relay with probe mode."
