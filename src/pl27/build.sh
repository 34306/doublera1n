#!/bin/bash
# Build PreferenceLoader27.dylib (arm64e + arm64, ad-hoc signed) into payload/device/.
# Needs Xcode (swiftc + clang for iphoneos). No theos.
set -euo pipefail
cd "$(dirname "$0")"
OUT=${1:-../../payload/device}
SDK=$(xcrun -sdk iphoneos --show-sdk-path)
B=$(mktemp -d /tmp/pl27-build.XXXXXX); trap 'rm -rf "$B"' EXIT
NAME=PreferenceLoader27
INSTALL=/var/jb/Library/MobileSubstrate/DynamicLibraries/$NAME.dylib
for A in arm64e arm64; do
    T=$A-apple-ios16.0
    mkdir -p "$B/$A"
    xcrun -sdk iphoneos swiftc -target $T -sdk "$SDK" -O -parse-as-library -module-name $NAME \
        -wmo -emit-object -o "$B/$A/swift.o" bridge.swift Support/PLSwiftString.swift
    for f in loader.m bridge.m Support/PLHeap.m Support/PLSwiftMeta.m; do
        xcrun -sdk iphoneos clang -target $T -isysroot "$SDK" -fobjc-arc -fblocks -O2 -ISupport \
            -Wall -Wno-unused-function -c "$f" -o "$B/$A/$(basename "${f%.m}").o"
    done
    xcrun -sdk iphoneos swiftc -target $T -sdk "$SDK" -emit-library -module-name $NAME \
        -o "$B/$A/$NAME.dylib" "$B/$A"/*.o \
        -Xlinker -install_name -Xlinker "$INSTALL" \
        -framework Foundation -framework UIKit -framework QuartzCore
done
lipo -create "$B/arm64e/$NAME.dylib" "$B/arm64/$NAME.dylib" -output "$B/$NAME.dylib"
codesign -f -s - "$B/$NAME.dylib"
mkdir -p "$OUT"
cp "$B/$NAME.dylib" "$OUT/$NAME.dylib"
cp $NAME.plist "$OUT/$NAME.plist"
echo "built $OUT/$NAME.dylib"
