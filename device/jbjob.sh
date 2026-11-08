#!/var/jb/usr/bin/zsh
# jbjob <plist> : replace the launchd job whose Label is in <plist> (system / user/501 domain)
L=/var/jb/usr/bin/launchctl; P=$1
label=$(sed -n '/<key>Label<\/key>/{n;s/.*<string>\(.*\)<\/string>.*/\1/p;}' "$P" | head -1)
dom=system
for d in system user/501; do $L print $d/$label >/dev/null 2>&1 && { dom=$d; break; }; done
$L bootout $dom/$label >/dev/null 2>&1; bo=$?
for i in 1 2 3 4 5 6 7 8 9 10; do $L print $dom/$label >/dev/null 2>&1 || break; sleep 0.5; done
for i in 1 2 3 4 5 6 7 8 9 10; do
  $L bootstrap $dom "$P" 2>/dev/null; bs=$?
  [ $bs -ne 17 ] && [ $bs -ne 37 ] && break     # EEXIST / EALREADY: old instance still being torn down
  sleep 1
done
echo "jbjob: $label ($dom) bootout $bo bootstrap $bs"; exit $bs
