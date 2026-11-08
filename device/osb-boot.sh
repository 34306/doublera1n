#!/var/jb/usr/bin/zsh
# OS B per-boot fixups, run by jbloader (root, launchd bootstrap port adopted). Editable on-device.
export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin
mkdir -p /var/jb/var/log; exec >> /var/jb/var/log/osb-boot.log 2>&1
echo "=== osb-boot $(date)"
# 0. corerepaird (parts authenticity, Lynx) only talks to the SEP, which never comes up on OS B. Its idle-time
#    maintenance run hits REQUIRE(!booted) in AppleSEPUserClient::DispatchUserClientLynxGetCPSN -> kernel panic.
#    The patched kernel returns an error there, but the other Lynx selectors still panic on a missing xART
#    endpoint, so keep the daemon off in OS B (launchd's disabled db is on DataB; stock iOS is unaffected).
launchctl disable system/com.apple.corerepaird 2>/dev/null
launchctl bootout system/com.apple.corerepaird 2>/dev/null && echo "corerepaird: booted out"
# 1. patched daemons (/var/jb copies) replace their launchd jobs.
#    securityd first: until obkeychain is in, the keychain (Wi-Fi password, pairing, ...) is unreadable.
#    Jobs listed in /cores/osb-cache-jobs.txt already start from the launchd cache override (jbinit bindfs
#    /jbin/xpc -> /System/Library/xpc) with the right program - they are skipped (no bootout/bootstrap, no restart).
J=/var/jb/Library/OSBDaemons
cached=()
if mount | grep -q " on /System/Library/xpc "; then
  cached=(${(f)"$(cat /cores/osb-cache-jobs.txt 2>/dev/null)"})
  echo "launchd cache override active: ${cached[*]}"
else
  echo "launchd cache override NOT active - swapping every OSBDaemons job"
fi
first=(com.apple.securityd com.apple.mobileactivationd)
for l in $first; do (( ${cached[(Ie)$l]} )) && continue; [ -f $J/$l.plist ] && jbjob $J/$l.plist; done
for p in $J/*.plist; do l=${${p:t}%.plist}; (( ${first[(Ie)$l]} || ${cached[(Ie)$l]} )) || jbjob $p; done
# rootless icons: sandbox read token for /private/var/jb consumed by systemhook in iconservicesagent
sbextissue
# demand-launched agents whose MachService port is only created on first launch after a re-bootstrap
for l in com.apple.iconservices.iconservicesagent; do
  [ -f $J/$l.plist ] && launchctl kickstart user/501/$l >/dev/null 2>&1
done
# 2. activation (hactivation path in the patched mobileactivationd)
maactivate
# 3. persona 99 for Sileo's spawnAsRoot
personaalloc
# 4. PosterBoard wallpaper repair watcher (long-running)
ps -ax -o comm= | grep -q "^/var/jb/usr/bin/pfwatch$" || (nohup /var/jb/usr/bin/pfwatch >/dev/null 2>&1 &)
# 5. background (jbloader starts sshd only after this script returns)
(
  # Wi-Fi: wifid's first auto-join ran against the stock securityd and could not read the password
  sleep 15
  if ! ifconfig en0 2>/dev/null | grep -q "status: active"; then
    echo "wifi: en0 not associated 15s after securityd swap -> restarting wifid"
    launchctl kickstart -k system/com.apple.wifid
  fi
  # tweak injection (obhook in launchd -> TweakLoader/ElleKit + systemhook), once SpringBoard is settled.
  # Kill switch: touch /var/jb/.obhook_noauto  (then `obhookctl enable` by hand)
  if [ ! -e /var/jb/.obhook_noauto ]; then
    for i in {1..60}; do
      line=$(ps -ax -o etime=,comm= | grep "SpringBoard.app/SpringBoard$" | head -1); t=${${=line}[1]}
      [[ -n $t && $t != 00:0* && $t != 00:1* ]] && break      # SpringBoard up >= 20 s
      sleep 5
    done
    obhookctl enable
    # rootless icons, all before the one respring: until now the stock iconservicesagent could not read /var/jb, so
    # it rendered the /var/jb apps as blank (white) icons and stored those in the IconsCache. Restart it with
    # systemhook (consumes the /var/jb read token), wait for THIS instance to report the token, then re-register the
    # /var/jb apps: a new registration invalidates the cached blank images (the uicache wrapper's -a = per-app
    # uicache27 --path, never a LaunchServices rebuild). Only then respring, so SpringBoard loads the tweaks and asks
    # for fresh icons in the same pass. (Re-registering without a respring left the blank icons on screen.)
    R=/private/var/tmp/sbext.iconservicesagent.result
    rm -f $R
    launchctl kickstart -k user/501/com.apple.iconservices.iconservicesagent
    for i in {1..40}; do grep -q "consume OK" $R 2>/dev/null && break; sleep 0.5; done
    if grep -q "consume OK" $R 2>/dev/null; then
      /var/jb/usr/bin/uicache -a >/dev/null 2>&1 && echo "icons: /var/jb apps re-registered $(date)"
    else
      echo "icons: iconservicesagent has no /var/jb token ($(cat $R 2>/dev/null))"
    fi
    sbreload
    echo "hooks: enabled + iconservicesagent restarted + respring $(date)"
    # whole system: restart the launchd jobs that started before injection was armed (skips core plumbing,
    # deny-listed daemons, drivers, ssh/jbloader, lsd and iconservicesagent; see the script).
    sleep 10
    /var/jb/usr/libexec/obhook-restart.sh > /var/jb/var/log/obhook-restart.log 2>&1
    echo "hooks: restarted $(wc -l < /var/jb/var/log/obhook-restart.log) pre-existing jobs $(date)"
  fi
) >> /var/jb/var/log/osb-boot.log 2>&1 &!
echo "=== osb-boot done $(date)"
