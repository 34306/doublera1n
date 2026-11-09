#!/var/jb/usr/bin/zsh
# dualboot: install every OS B userland fix (run by `dualboot.py provision` over SSH, OS B running).
# Idempotent: a file is only rewritten when its content differs (previous copy kept as <file>.dualboot-prev),
# packages are only installed when missing, and obkeychain.master is NEVER regenerated once it exists
# (that would make every keychain item unreadable). Writes only to DataB and to our own directory
# /private/preboot/Cryptexes/ob on the shared Preboot volume.
P=${1:-/var/jb/tmp/dualboot-payload}
export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin
mkdir -p /var/jb/var/log
LOG=/var/jb/var/log/dualboot-provision.log
exec > >(tee -a $LOG) 2>&1
print -r -- "=== dualboot provision $(date)  payload $P"
[[ -d $P ]] || { print -r -- "!! payload dir $P missing"; exit 1; }
FAIL=0
step() { print -r -- "== $*"; }
bad()  { print -r -- "  !! $*"; FAIL=1; }

# inst <src> <dst> <mode> [owner]
inst() {
    local s=$1 d=$2 m=$3 o=${4:-root:wheel}
    [[ -f $s ]] || { bad "missing payload file $s"; return 1; }
    mkdir -p ${d:h}
    if [[ -f $d ]] && cmp -s $s $d; then
        chmod $m $d; chown $o $d
        return 0
    fi
    [[ -f $d ]] && cp -p $d $d.dualboot-prev
    cp $s $d.dualboot-new && chmod $m $d.dualboot-new && chown $o $d.dualboot-new && mv -f $d.dualboot-new $d \
        && print -r -- "  + $d" || bad "install $d"
}
marker() { [[ -e $1 ]] || { : > $1 && print -r -- "  + $1"; }; chmod $2 $1; chown ${3:-root:wheel} $1; }

step "wait for the first-boot data directories"
for d in /private/var/Keychains /private/var/root/Library/Lockdown /private/var/wireless/Library; do
    for i in {1..60}; do [[ -d $d ]] && break; sleep 2; done
    [[ -d $d ]] || bad "$d never appeared (has OS B finished its first boot?)"
done

step "Preboot /private/preboot/Cryptexes/ob (coreauthd guard, obhook, systemhook)"
OB=/private/preboot/Cryptexes/ob
mkdir -p $OB && chown root:wheel $OB && chmod 755 $OB
inst $P/device/obcoreauth.dylib $OB/ca.dylib 755
inst $P/boot/obhook.dylib        $OB/obhook.dylib 755
inst $P/device/systemhook.dylib $OB/systemhook.dylib 755

step "OS B dylibs + markers in the daemons' own data directories"
inst $P/device/obfdr.dylib /private/var/wireless/Library/obfdr.dylib 755
marker /private/var/wireless/Library/.obfdr-sik-bypass 644
inst $P/device/obkeychain.dylib /private/var/Keychains/obkeychain.dylib 755
marker /private/var/Keychains/.obkeychain 600
M=/private/var/Keychains/obkeychain.master
if [[ ! -s $M ]]; then
    dd if=/dev/urandom of=$M bs=32 count=1 2>/dev/null && print -r -- "  + $M (new master key)"
fi
chown 64:0 $M; chmod 600 $M     # _securityd must own it ("master key unavailable" otherwise)
inst $P/device/obpair.dylib /private/var/root/Library/Lockdown/obpair.dylib 755
marker /private/var/root/Library/Lockdown/.obpair-fallback 600

step "patched daemons (/var/jb copies, swapped in by osb-boot.sh or started by the launchd cache override)"
FW=/var/jb/System/Library/Frameworks
inst $P/daemons/ctkd       $FW/CryptoTokenKit.framework/ctkd 755
inst $P/daemons/coreauthd  $FW/LocalAuthentication.framework/Support/coreauthd 755
inst $P/daemons/commcenter $FW/CoreTelephony.framework/Support/CommCenter 755
inst $P/daemons/securityd  /var/jb/usr/libexec/securityd 755
inst $P/daemons/lockdownd  /var/jb/usr/libexec/lockdownd 755
mkdir -p /var/jb/Library/OSBDaemons
for f in $P/jobs/*.plist; do inst $f /var/jb/Library/OSBDaemons/${f:t} 644; done

step "boot helpers, injection userland, helpers, tools"
inst $P/scripts/jbjob.sh           /var/jb/usr/bin/jbjob 755
inst $P/scripts/obhook-restart.sh   /var/jb/usr/libexec/obhook-restart.sh 755
for t in obhookctl sbextissue personaalloc pfwatch lsq sysapps stackdump mkbstate kcq kcacl dnsq; do
    inst $P/device/$t /var/jb/usr/bin/$t 755
done
inst $P/device/lsq /var/jb/usr/libexec/lsq 755
[[ -f /var/jb/etc/obhook.deny ]] || inst $P/device/obhook.deny /var/jb/etc/obhook.deny 644   # user-editable

step "uicache: uicache27 + wrapper (-a never rebuilds the LaunchServices DB) + dpkg divert"
inst $P/device/uicache27            /var/jb/usr/libexec/uicache27 755
if ! dpkg-divert --list 2>/dev/null | grep -q " /var/jb/usr/bin/uicache "; then
    dpkg-divert --no-rename --add --divert /var/jb/usr/libexec/uicache.dpkg /var/jb/usr/bin/uicache >/dev/null \
        && print -r -- "  + divert /var/jb/usr/bin/uicache -> /var/jb/usr/libexec/uicache.dpkg" || bad "uicache divert"
fi
inst $P/scripts/uicache.wrapper.sh  /var/jb/usr/bin/uicache 755

step "libkrw0 plugin (the bootstrap's libkrw0 depends on libkrw0-plugin: without one apt/Sileo refuse every install)"
# libkrw0-tfp0 (Procursus, sha256 be27d936...) only satisfies the dependency; there is no kernel r/w for userland
# on 2nd Data, so libkrw calls keep failing cleanly
if [[ "$(dpkg-query -W -f='${Status}' libkrw0-tfp0 2>/dev/null)" != "install ok installed" ]]; then
    dpkg -i $P/pkgs/libkrw0-tfp0_1.1.1-2_iphoneos-arm64.deb >/dev/null 2>&1 && print -r -- "  + libkrw0-tfp0" \
        || bad "dpkg -i libkrw0-tfp0"
fi

step "ElleKit (tweak loader; injection itself comes from obhook in launchd)"
if ! dpkg-divert --list 2>/dev/null | grep -q "ellekit-loader"; then
    dpkg-divert --local --rename --divert /var/jb/etc/rc.d/ellekit-loader.osb-disabled \
        --add /var/jb/etc/rc.d/ellekit-loader >/dev/null && print -r -- "  + divert rc.d/ellekit-loader"
fi
if [[ "$(dpkg-query -W -f='${Status}' ellekit 2>/dev/null)" != "install ok installed" ]]; then
    dpkg -i $P/pkgs/ellekit.deb >/dev/null 2>&1 && print -r -- "  + ellekit" || bad "dpkg -i ellekit"
fi
mkdir -p /var/jb/Library/MobileSubstrate/DynamicLibraries

step "PreferenceLoader27 (tweak settings rows in the iOS 27 SwiftUI Settings sidebar; needs the preferenceloader package)"
inst $P/device/PreferenceLoader27.dylib /var/jb/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader27.dylib 755
inst $P/device/PreferenceLoader27.plist /var/jb/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader27.plist 644
step "obremoteui (RemoteUI web views: the diagnostics-mode WebKit assert crashes Setup's Apple Account pages)"
inst $P/device/obremoteui.dylib /var/jb/Library/MobileSubstrate/DynamicLibraries/obremoteui.dylib 755
inst $P/device/obremoteui.plist /var/jb/Library/MobileSubstrate/DynamicLibraries/obremoteui.plist 644

step "Sileo (re-signed for OS B: uid 501, persona-based root helper, reports palera1n rootless)"
if [[ "$(dpkg-query -W -f='${Status}' org.coolstar.sileo 2>/dev/null)" != "install ok installed" ]]; then
    SILEO=1 dpkg -i $P/pkgs/sileo.deb >/dev/null 2>&1 && print -r -- "  + org.coolstar.sileo" || bad "dpkg -i sileo"
fi
T=/var/jb/tmp/dualboot-sileo; rm -rf $T; mkdir -p $T && tar -C $T -xf $P/pkgs/Sileo.app.tar
if ! cmp -s $T/Sileo.app/Sileo /var/jb/Applications/Sileo.app/Sileo; then
    rm -rf /var/jb/Applications/Sileo.app && mv $T/Sileo.app /var/jb/Applications/Sileo.app \
        && print -r -- "  + patched Sileo.app" || bad "Sileo.app replace"
fi
rm -rf $T
chown -R root:wheel /var/jb/Applications/Sileo.app
chmod 4755 /var/jb/Applications/Sileo.app/giveMeRoot
mkdir -p /var/jb/var/lib/apt/sileolists /var/jb/var/cache/apt/archives/partial
chown -R 501:501 /var/jb/var/lib/apt/sileolists /var/jb/var/cache/apt/archives/partial

step "per-boot script (installed last: from now on jbloader hands every boot to it)"
inst $P/scripts/osb-boot.sh /var/jb/usr/libexec/osb-boot.sh 755

step "register /var/jb apps"
/var/jb/usr/bin/uicache -a >/dev/null 2>&1 || bad "uicache -a"

if (( FAIL )); then print -r -- "=== provision finished WITH ERRORS (see above)"; exit 1; fi
print -r -- "=== provision OK $(date)"
