#!/var/jb/usr/bin/dash
set -eu
JB=/var/jb
export PATH="$JB/usr/bin:$JB/bin:$JB/usr/sbin:$JB/sbin:/usr/bin:/bin:/usr/sbin:/sbin"

fail() { printf '%s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'Run this through ./boot.sh ssh as root.'
mode=${1:-init}
case "$mode" in init|restart) ;; *) fail 'Expected init or restart.' ;; esac

marker="$JB/.root-password-initialized"
if [ ! -e "$marker" ]; then
    found=
    while IFS=: read -r account password uid fields; do
        [ "$account" = root ] || continue
        [ "$uid" = 0 ] && [ -n "$fields" ] || fail 'Invalid root entry in master.passwd.'
        found=yes
        break
    done < "$JB/etc/master.passwd"
    [ "$found" = yes ] || fail 'No root entry in master.passwd.'
    case "$password" in
        ''|'!'|'*')
            printf '%s\n' alpine | "$JB/usr/sbin/pw" usermod root -h 0
            printf '%s\n' 'Root password initialized to alpine.'
            ;;
    esac
    (umask 077; : > "$marker")
fi
[ "$mode" = restart ] || exit 0

sshd="$JB/usr/sbin/sshd"
pidfile="$JB/var/run/sshd.pid"
effective=$("$sshd" -T -p 22 -o "PidFile=$pidfile" -C user=root,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22)
root_login=
password_login=
while read -r option value; do
    case "$option" in
        permitrootlogin) root_login=$value ;;
        passwordauthentication) password_login=$value ;;
    esac
done <<EOF
$effective
EOF
[ "$root_login" = yes ] && [ "$password_login" = yes ] || fail 'Allow PermitRootLogin yes and PasswordAuthentication yes in /var/jb/etc/ssh/sshd_config first.'

[ -r "$pidfile" ] || fail 'Cannot identify the current SSH listener: sshd.pid is missing.'
read -r listener < "$pidfile"
case "$listener" in ''|*[!0-9]*) fail 'Invalid SSH listener PID.' ;; esac
[ "$listener" -gt 1 ] || fail 'Invalid SSH listener PID.'
inspector="$JB/usr/bin/ssh-listener"
[ -x "$inspector" ] || fail 'Copy payload/boot/ssh-listener to /var/jb/usr/bin/ssh-listener and chmod 755 it first.'
parent=$("$inspector" "$listener") || fail 'Cannot verify the SSH listener and supervisor; leaving processes alone.'
case "$parent" in ''|*[!0-9]*) fail 'Cannot identify the SSH supervisor.' ;; esac
[ "$parent" -ge 1 ] && [ "$parent" != "$listener" ] || fail 'Invalid SSH supervisor PID.'
if [ "$parent" -gt 1 ]; then
    kill -TERM "$parent"
fi
kill -TERM "$listener"
attempt=0
while kill -0 "$listener" 2>/dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || fail 'The old SSH listener did not stop. The existing root session is still available.'
    sleep 0.1
done
mkdir -p "$JB/var/log" "$JB/var/run"
"$sshd" -p 22 -o "PidFile=$pidfile" -E "$JB/var/log/sshd.log"
attempt=0
while [ "$attempt" -lt 50 ]; do
    if [ -r "$pidfile" ]; then
        read -r replacement < "$pidfile"
        case "$replacement" in
            ''|*[!0-9]*) ;;
            *)
                if [ "$replacement" -gt 1 ] && [ "$replacement" != "$listener" ] && kill -0 "$replacement" 2>/dev/null; then
                    printf '%s\n' 'Root password login enabled on port 22; the current SSH session was preserved.'
                    exit 0
                fi
                ;;
        esac
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
fail 'The replacement SSH listener did not start. Inspect /var/jb/var/log/sshd.log from the existing root session.'
