#!/var/jb/usr/bin/zsh
# OS B: after `obhookctl enable`, restart the launchd jobs that started before injection was
# armed (no ElleKit libinjector mapped) so tweaks reach the whole system, not only new spawns.
# usage: obhook-restart.sh [-n]   (-n = dry run: only list)
export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin
dry=0; [[ $1 == -n ]] && dry=1
# never touched: PID 1 / our loader + ssh (only way in), obhook's hard+default deny lists, and core plumbing whose
# restart cascades (prefs, FS events, app lifecycle, pairing, display, power, network for the session)
skip=(launchd jbloader sshd zsh amfid trustd securityd configd notifyd logd logd_helper opendirectoryd keybagd
      watchdogd dropbear diskarbitrationd syslogd usbmuxd mobile_obliterator restored_external aslmanager GSSCred
      runningboardd cfprefsd fseventsd lockdownd SpringBoard backboardd wifid mDNSResponder powerd thermalmonitord
      kernelmanagerd seputil UserEventAgent pfwatch containermanagerd containermanagerd_system usermanagerd
      mobileactivationd CommCenter
      lsd iconservicesagent)
# lsd: restarting LaunchServices mid-session makes iconservicesagent garbage-collect its icon store, leaving the
# /var/jb app icons blank ("Failed to get unit N from store"); iconservicesagent is restarted by osb-boot instead.
n=0
for dom in system user/501; do
  launchctl print $dom 2>/dev/null | sed -n '/services = {/,/}/p' | while read pid st label; do
    [[ $pid == <-> ]] && (( pid > 2 )) || continue
    [[ $label == UIKitApplication:* ]] && continue
    comm=$(ps -o comm= -p $pid 2>/dev/null); comm=${comm##*/}
    [[ -z $comm ]] && continue
    (( ${skip[(Ie)$comm]} )) && continue
    [[ $comm == com.apple.DriverKit-* || $comm == IOMFB* || $label == com.apple.iomfb* ]] && continue   # drivers/display
    lsimg $pid 2>/dev/null | grep -q libinjector.dylib && continue
    n=$((n+1))
    if (( dry )); then echo "would restart $dom/$label ($comm pid $pid)"
    else launchctl kickstart -k $dom/$label >/dev/null 2>&1; echo "restarted $dom/$label ($comm) rc=$?"; sleep 0.1; fi
  done
done
