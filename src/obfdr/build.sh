#!/bin/sh
# Build the CommCenter-only FDR sik-verification bypass for both device ABIs,
# and obradio, the airplane-mode toggle used to force a baseband reset while
# testing this path. Only obfdr.dylib is deployed; obradio is a manual tool.
#
# The data-activation gate is NOT handled here. Patching the DataSettings
# vtable from inside CommCenter cannot work: vm_protect on those
# __DATA_CONST pages returns KERN_PROTECTION_FAILURE because max protection no
# longer carries write once dyld has applied fixups, and the device boots SPTM,
# so the process cannot grant itself write. That gate is a binary patch of
# CommCenter instead.

set -eu
BASE="$(cd "$(dirname "$0")" && pwd)"
LDID=$(command -v ldid || true)
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
OUT="$BASE/obfdr.dylib"

"$LDID" -v 2>&1 | grep -q "Link Identity Editor" \
    || { echo "[!] ldid at $LDID cannot run here; brew install ldid-procursus" >&2; exit 1; }

# obari.cpp rides in the same dylib rather than a second one, because a new
# dylib would need its own LC_LOAD_WEAK_DYLIB in CommCenter, while this file
# is already loaded. It is C++ because
# Ari::LogConfig's callback takes std::string by value and the ABI has to match
# libc++ exactly. It is inert unless its own marker exists, so it cannot affect
# the FDR path it shares a binary with.
# Compiled per source rather than in one invocation, because -std=c++17 cannot
# be passed alongside a C file.
for arch in arm64 arm64e; do
    COMMON="-arch $arch -miphoneos-version-min=15.0 -isysroot $SDK -O2 -Wall -Wextra -Werror"
    # shellcheck disable=SC2086
    xcrun -sdk iphoneos clang $COMMON -c -o "$BASE/obfdr_$arch.o" "$BASE/obfdr.c"
    # shellcheck disable=SC2086
    xcrun -sdk iphoneos clang++ $COMMON -std=c++17 -c -o "$BASE/obari_$arch.o" "$BASE/obari.cpp"
    xcrun -sdk iphoneos clang++ -arch "$arch" -miphoneos-version-min=15.0 \
        -isysroot "$SDK" -dynamiclib \
        -Wl,-not_for_dyld_shared_cache -install_name /private/var/wireless/Library/obfdr.dylib \
        -framework CoreFoundation \
        -o "$BASE/obfdr_$arch.dylib" "$BASE/obfdr_$arch.o" "$BASE/obari_$arch.o"
    rm -f "$BASE/obfdr_$arch.o" "$BASE/obari_$arch.o"
done

lipo -create "$BASE/obfdr_arm64.dylib" "$BASE/obfdr_arm64e.dylib" -output "$OUT"
rm -f "$BASE/obfdr_arm64.dylib" "$BASE/obfdr_arm64e.dylib"
"$LDID" -S -Cadhoc "$OUT"

archs=$(lipo -archs "$OUT")
case " $archs " in *" arm64 "*) ;; *) echo "[!] missing arm64 slice" >&2; exit 1 ;; esac
case " $archs " in *" arm64e "*) ;; *) echo "[!] missing arm64e slice" >&2; exit 1 ;; esac
for arch in arm64 arm64e; do
    # No interposing. The os_variant_is_recovery route cannot work from a
    # late-loaded dylib against a shared-cache-internal call, so an
    # __interpose section reappearing here means the dylib regressed to it.
    otool -arch "$arch" -l "$OUT" | grep -q 'sectname __interpose' \
        && { echo "[!] obfdr $arch unexpectedly contains an interpose section" >&2; exit 1; }
done
# The whole mechanism is this one libFDR export. If it is not imported, the
# dylib loads, logs and changes nothing.
strings -a "$OUT" | grep -q '^AMFDRSealingMapRegisterCustomQueryProvider$' \
    || { echo "[!] the libFDR registration symbol is absent" >&2; exit 1; }
for key in CertificateSecurityMode EffectiveSecurityModeSEP EffectiveProductionStatusAp; do
    strings -a "$OUT" | grep -qx "$key" \
        || { echo "[!] demotion-state key $key is absent" >&2; exit 1; }
done
strings -a "$OUT" | grep -q '^CommCenter$' \
    || { echo "[!] the CommCenter process guard is absent" >&2; exit 1; }
strings -a "$OUT" | grep -q '^/private/var/wireless/Library/\.obfdr-sik-bypass$' \
    || { echo "[!] the FDR marker gate is absent" >&2; exit 1; }
# The ARI tracer must stay gated on its own Data-volume marker, and must still
# be reaching Ari::LogConfig by its exact mangled name. A rename in a future
# build would otherwise fail silently at dlsym and look like "no ARI traffic".
strings -a "$OUT" | grep -qx '/var/wireless/Library/Preferences' \
    || { echo "[!] the ARI candidate directory list is absent" >&2; exit 1; }
strings -a "$OUT" | grep -q '^_ZN3Ari9LogConfigEjPFvjPKcEPFvi' \
    || { echo "[!] the Ari::LogConfig symbol is absent" >&2; exit 1; }
[ -z "$("$LDID" -e "$OUT")" ] \
    || { echo "[!] obfdr unexpectedly carries entitlements" >&2; exit 1; }

echo "[+] $OUT ($archs, CommCenter-only marker-gated FDR sik bypass)"

# obradio. arm64e only: it runs on the device by hand, never in the arm64 slice
# of an injected payload. RadiosPreferences is private, so it is resolved at
# runtime and nothing here links it.
RADIO="$BASE/obradio"
xcrun -sdk iphoneos clang -arch arm64e -miphoneos-version-min=15.0 \
    -isysroot "$SDK" -O2 -Wall -Wextra -Werror -fobjc-arc \
    -framework Foundation -o "$RADIO" "$BASE/obradio.m"
"$LDID" -S "$RADIO"
strings -a "$RADIO" | grep -q '^RadiosPreferences$' \
    || { echo "[!] obradio does not reference RadiosPreferences" >&2; exit 1; }
echo "[+] $RADIO (arm64e, airplane-mode toggle for forcing a baseband reset)"
