#!/usr/bin/env python3
"""Patched copies of System daemons for OS B (sealed System stays untouched):
   apply the userland patch records (lib/patchfinder) -> re-sign ad-hoc with the ORIGINAL identifier + entitlements ->
   job plist = the daemon's launchd-cache entry with Program/ProgramArguments[0] -> /var/jb copy.
   Usage: mkdaemon.py <name> <device path> [--weak-dylib <path-on-device>]...
   out: $OSB_WORK/daemons/<name> (binary), $OSB_WORK/daemons/<label>.plist"""
import os, plistlib, struct, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__)); JB = os.path.dirname(HERE)
sys.path.insert(0, JB); sys.path.insert(0, HERE); import kpf, osbcfg
ROOTFS = osbcfg.ROOTFS
OUT = osbcfg.work('daemons'); os.makedirs(OUT, exist_ok=True)

def sh(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    if r.returncode: sys.exit(f"!! {' '.join(a)}\n{r.stdout}{r.stderr}")
    return r.stdout + r.stderr

def main():
    name, devpath, *rest = sys.argv[1:]
    weak = [rest[i + 1] for i in range(len(rest)) if rest[i] == '--weak-dylib']
    stock = os.path.join(ROOTFS, devpath.lstrip('/'))
    raw = bytearray(open(stock, 'rb').read())
    js = osbcfg.rec(f'{name}.json')
    if not os.path.exists(js):
        import json, pf
        json.dump(pf.resolve('userland', name, stock), open(js, 'w'), indent=1)
    recs = kpf.load_records([js]) if os.path.getsize(js) else []
    words = kpf.records_to_words(bytes(raw), recs)
    for off, o, n in words: struct.pack_into('<I', raw, off, n)
    out = os.path.join(OUT, name); open(out, 'wb').write(raw)
    if weak:
        tmp = out + '.tmp'
        for w in weak:
            sh(sys.executable, os.path.join(HERE, 'insert_dylib.py'), out, tmp, w); os.replace(tmp, out)
    ents = out + '.ents.plist'
    open(ents, 'w').write(sh('codesign', '-d', '--entitlements', '-', '--xml', stock) or '<plist><dict/></plist>')
    # <records dir>/<name>.ents-add.plist: entitlements an ad-hoc copy needs that the Apple-signed (platform) original
    # got for free, e.g. lockdownd -> com.apple.springboard.CFUserNotification (SpringBoard's
    # FBServiceClientAuthenticator refuses the Trust alert otherwise: "Entitlement ... is required")
    add = osbcfg.rec(f'{name}.ents-add.plist')
    if os.path.exists(add):
        txt = open(ents).read(); txt = txt[:txt.index('</plist>') + 8]      # sh() appends codesign's stderr
        e = plistlib.loads(txt.encode()); extra = plistlib.load(open(add, 'rb')); e.update(extra)
        plistlib.dump(e, open(ents, 'wb'), fmt=plistlib.FMT_XML)
        print(f"{name}: + entitlements {sorted(extra)}")
    ident = [l.split('=', 1)[1] for l in sh('codesign', '-dvvv', stock).splitlines() if l.startswith('Identifier=')][0]
    sh('ldid', f'-S{ents}', f'-I{ident}', out)
    cd = [l.split('=', 1)[1] for l in sh('codesign', '-dvvv', out).splitlines() if l.startswith('CDHash=')][0]
    # job plist from the launchd cache
    cache = plistlib.load(open(os.path.join(ROOTFS, 'System/Library/xpc/launchd.plist'), 'rb'))
    jobs = [(k, j) for k, j in cache['LaunchDaemons'].items()
            if j.get('Program') == devpath or (j.get('ProgramArguments') or [None])[0] == devpath]
    if not jobs: sys.exit(f"!! no cache job runs {devpath}")
    # several cache entries can share one Label (CommCenter: com.apple.CommCenter.plist and
    # com.apple.CommCenter-noncellular.plist): keep the one whose file name is <Label>.plist
    by_label = {}
    for k, j in jobs:
        if j['Label'] not in by_label or os.path.basename(k) == j['Label'] + '.plist':
            by_label[j['Label']] = j
    target = '/var/jb' + devpath
    for j in by_label.values():
        j = dict(j)
        if 'Program' in j: j['Program'] = target
        if 'ProgramArguments' in j: j['ProgramArguments'] = [target] + list(j['ProgramArguments'][1:])
        plistlib.dump(j, open(os.path.join(OUT, j['Label'] + '.plist'), 'wb'), fmt=plistlib.FMT_XML)
        print(f"{name}: {len(recs)} records/{len(words)} words, weak={weak}, id={ident}, cdhash={cd}, job={j['Label']} -> {target}")

if __name__ == '__main__':
    main()
