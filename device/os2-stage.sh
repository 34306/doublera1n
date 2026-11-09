#!/var/jb/usr/bin/zsh
# 2nd iOS staging (DEVELOPING FEATURE - not device-tested yet). Runs on 2nd Data as root; dualboot.py os2 uploads it
# with os2vol to /var/jb/tmp/dualboot-os2 and calls it around the copies it streams over SSH:
#   os2-stage.sh prepare <build>   create OS2System / OS2Data (os2vol), mount them rw on $M/sys and $M/data,
#                                  create Preboot:/Cryptexes/ob/os2/<build>/{OS,App} (this build's cryptex content)
#   os2-stage.sh finish <build>    OS2System: /System/Cryptexes/{OS,App} and /System/Library/Caches/com.apple.dyld
#                                  -> the Preboot copy, marker /.dualboot-os2; OS2Data: markers; unmount both
#   os2-stage.sh unmount           unmount both (after an error)
#   os2-stage.sh remove            unmount, delete both volumes (os2vol), delete Preboot:/Cryptexes/ob/os2
# Writes only to OS2System, OS2Data and Preboot:/Cryptexes/ob/os2. Stock iOS and DataB are never touched.
export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin
HERE=${0:A:h}
V=$HERE/os2vol
M=/var/jb/tmp/os2
OB=/private/preboot/Cryptexes/ob
fail() { print -r -- "!! $*"; exit 1; }
is_mounted() { mount | grep -q " on $1 (" }

preboot_rw() {
    local t=$OB/.os2-write-test
    mkdir -p $OB 2>/dev/null
    if ! { : > $t } 2>/dev/null; then
        mount -uw /private/preboot || fail "cannot make Preboot writable"
        : > $t || fail "Preboot still not writable"
    fi
    rm -f $t
}

umount_all() {
    sync
    for d in $M/sys $M/data; do
        is_mounted $d && { umount $d || umount -f $d || print -r -- "!! cannot unmount $d"; }
    done
    return 0
}

case $1 in
prepare)
    B=$2; [[ -n $B ]] || fail "usage: prepare <build>"
    out=$($V create) || { print -r -- "$out"; fail "os2vol create failed"; }
    print -r -- "$out"
    SYS=$(print -r -- "$out" | awk '/^OS2SYS /{print $2}')
    DATA=$(print -r -- "$out" | awk '/^OS2DATA /{print $2}')
    [[ $SYS == disk<->s<-> && $DATA == disk<->s<-> ]] || fail "os2vol did not report both volumes"
    mkdir -p $M/sys $M/data
    is_mounted $M/sys  || mount_apfs /dev/$SYS  $M/sys  || fail "mount OS2System ($SYS)"
    is_mounted $M/data || mount_apfs /dev/$DATA $M/data || fail "mount OS2Data ($DATA)"
    if [[ -f $M/sys/.dualboot-os2 && "$(cat $M/sys/.dualboot-os2)" != $B ]]; then
        print -r -- "OS2System holds iOS build $(cat $M/sys/.dualboot-os2): replacing it with $B"
    fi
    preboot_rw
    rm -rf $OB/os2; mkdir -p $OB/os2/$B/OS $OB/os2/$B/App || fail "mkdir $OB/os2/$B"
    chown -R root:wheel $OB/os2; chmod 755 $OB $OB/os2 $OB/os2/$B
    print -r -- "FREE $(df -k /private/var | awk 'NR==2{print $4}')"
    print -r -- "MOUNTED sys=$SYS data=$DATA"
    ;;
finish)
    B=$2; [[ -n $B ]] || fail "usage: finish <build>"
    S=$M/sys; D=$M/data; C=$OB/os2/$B
    is_mounted $S && is_mounted $D || fail "OS2System/OS2Data are not mounted (run prepare first)"
    grep -q "<string>$B</string>" $S/System/Library/CoreServices/SystemVersion.plist 2>/dev/null \
        || fail "OS2System does not hold iOS build $B"
    [[ -d $C/OS/System/Library/Caches/com.apple.dyld ]] || fail "no shared cache in $C/OS"
    # the canonical cryptex directories libignition opens (and dyld's fallback search) -> this build's copy
    mkdir -p $S/System/Cryptexes
    for c in OS App; do rm -rf $S/System/Cryptexes/$c; ln -s $C/$c $S/System/Cryptexes/$c; done
    rm -rf $S/System/Library/Caches/com.apple.dyld
    ln -s $C/OS/System/Library/Caches/com.apple.dyld $S/System/Library/Caches/com.apple.dyld
    mkdir -p $S/private/var; chmod 755 $S/private/var
    print -r -- $B > $S/.dualboot-os2
    # OS2Data: jbinit starts jbloader once /private/var/dualboot-setup.log exists
    [[ -d $D/mobile ]] || fail "OS2Data has no /private/var template (mobile/ missing)"
    mkdir -p $D/jb
    print -r -- "2nd iOS $B staged $(date)" > $D/dualboot-setup.log
    chown -R root:wheel $C; chmod -R go-w $C
    ls -la $S/System/Cryptexes $S/System/Library/Caches/com.apple.dyld
    umount_all
    is_mounted $S || is_mounted $D && fail "unmount failed"
    print -r -- "STAGED $B"
    ;;
unmount)
    umount_all
    ;;
remove)
    umount_all
    $V delete || fail "os2vol delete failed (nothing else was removed)"
    preboot_rw
    rm -rf $OB/os2 && print -r -- "removed $OB/os2"
    print -r -- "REMOVED"
    ;;
*)
    fail "usage: os2-stage.sh prepare|finish <build> | unmount | remove"
    ;;
esac
