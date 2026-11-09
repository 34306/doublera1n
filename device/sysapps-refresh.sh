#!/var/jb/usr/bin/zsh
# 2nd Data after a stock iOS update (developing): the system apps installed on DataB are still the old build's and
# fail at launch against the new shared cache (dyld "Symbol not found"). SystemAppMigrator does not update them from
# here (IXUpdatingAppInstallCoordinator: MIInstallerErrorDomain 128), so replace each installed bundle in place with
# the new build's copy: same container, same path, same executable name, owner _installd. The new binaries are in
# the new build's static trust cache. App data (Data/Application, group containers) is not touched.
#   sysapps-refresh.sh <new apps dir> <backup dir> <App.app:Executable>...
# Old bundles are moved to <backup dir>/<container UUID>/ (delete it once the apps work).
export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin
NEW=$1 BAK=$2; shift 2
[[ -d $NEW ]] || { print -r -- "!! $NEW missing"; exit 1; }
mkdir -p $BAK
n=0 same=0 missing=0
for pair in "$@"; do
    app=${pair%%:*} exe=${pair#*:}
    src=$NEW/$app
    [[ -d $src && -f $src/$exe ]] || { print -r -- "  ? $app: not in the new build"; continue; }
    dst=(/private/var/containers/Bundle/Application/*/$app(N))
    (( ${#dst} == 1 )) || { (( ${#dst} == 0 )) && (( missing += 1 )) || print -r -- "  ? $app: ${#dst} installed copies - skipped"; continue; }
    dst=$dst[1]
    if cmp -s $src/$exe $dst/$exe; then (( same++ )); continue; fi
    uuid=${dst:h:t}
    mkdir -p $BAK/$uuid
    rm -rf $BAK/$uuid/$app
    mv $dst $BAK/$uuid/$app || { print -r -- "!! $app: cannot move the old bundle"; continue; }
    if cp -a $src $dst && chown -R _installd:_installd $dst; then
        print -r -- "  + $app"; (( n++ ))
    else
        print -r -- "!! $app: copy failed - restoring the old bundle"
        rm -rf $dst; mv $BAK/$uuid/$app $dst
    fi
done
print -r -- "REFRESHED $n (unchanged $same, not installed $missing)"
