#!/var/jb/usr/bin/zsh
# OS B: /var/jb/usr/bin/uicache. Everything except -a/--all goes to the real uicache27.
# `uicache -a` (the uikittools dpkg trigger, run after every Sileo install of an app) must NOT rebuild the
# LaunchServices database: uicache27 --all rebuilds system+internal only, which drops the OS-cryptex
# extensions (com.apple.WebKit.WebContent/Networking/GPU -> Safari/App Store/WKWebViews load nothing,
# "Could not find matching appex record"). Instead register /var/jb/Applications apps one by one and
# unregister the ones whose bundle disappeared. Repair a damaged DB with: lsq -rebuild 1 1 1; uicache -a
REAL=/var/jb/usr/libexec/uicache27
LSQ=/var/jb/usr/libexec/lsq
LIST=/var/jb/var/lib/uicache.jbapps
all=0; respring=0; reg=0
for a in "$@"; do case $a in -a|--all) all=1;; -r|--respring) respring=1;; -p|--path|-u|--unregister|--path=*|--unregister=*) reg=1;; esac; done
if (( ! all )); then
  (( reg )) || exec $REAL "$@"
  # -p/-u: upstream uikittools-ng reports a failed (un)register on stderr but still exits 0; uicache27 exits 255.
  # Package scripts rely on the upstream behaviour, e.g. CocoaTop's preinst runs `uicache -u <app>` before the app
  # was ever installed, and a non-zero status there aborts the whole dpkg install.
  $REAL "$@" || print -ru2 -- "uicache: exit $? ignored (upstream uicache exits 0 here)"
  exit 0
fi
touch $LIST
for app in ${(f)"$(<$LIST)"}; do [[ -n $app && ! -d $app ]] && $LSQ -unreg "$app"; done
: >| $LIST.new
for app in /var/jb/Applications/*.app(N); do $REAL --path "$app" && print -r -- "$app" >> $LIST.new; done
mv -f $LIST.new $LIST
(( respring )) && /var/jb/usr/bin/sbreload
exit 0
