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

def sig_blobs(path):
    """{slot: blob} of the embedded code signature (thin Mach-O, or the arm64e slice of a fat one)."""
    b = open(path, 'rb').read(); base = 0
    if struct.unpack_from('>I', b)[0] == 0xcafebabe:
        n = struct.unpack_from('>I', b, 4)[0]
        sl = [struct.unpack_from('>IIIII', b, 8 + 20 * i) for i in range(n)]
        base = next((o for ct, st, o, _, _ in sl if ct == 0x0100000c and st & 0xffffff == 2), sl[0][2])
    if struct.unpack_from('<I', b, base)[0] != 0xfeedfacf: return {}
    ncmds = struct.unpack_from('<I', b, base + 16)[0]; off = base + 32; sig = None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', b, off)
        if cmd == 0x1d: sig = struct.unpack_from('<I', b, off + 8)[0]          # LC_CODE_SIGNATURE dataoff
        off += size
    if sig is None: return {}
    so = base + sig; out = {}
    for i in range(struct.unpack_from('>I', b, so + 8)[0]):
        slot, bo = struct.unpack_from('>II', b, so + 12 + 8 * i)
        out[slot] = b[so + bo:so + bo + struct.unpack_from('>I', b, so + bo + 4)[0]]
    return out

def stock_entitlements(stock, blobs):
    """XML entitlements of the Apple-signed original, as bytes, read from its signature (slot 5, 0xfade7171).
    `codesign -d --entitlements` is only a fallback (DER-only signature): its output differs between macOS versions
    (macOS 15 put nothing parsable on stdout for iOS 27 daemons -> ldid: "_assert(): plist != NULL")."""
    x = blobs.get(5)
    if x and x[:4] == b'\xfa\xde\x71\x71':
        xml = x[8:].rstrip(b'\0')
    else:
        r = subprocess.run(['codesign', '-d', '--entitlements', '-', '--xml', stock], capture_output=True)
        xml = r.stdout.strip()
        xml = xml[:xml.rindex(b'</plist>') + 8] if b'</plist>' in xml else b''
        if not xml:
            if 7 in blobs: sys.exit(f"!! cannot read the entitlements of {stock} (DER only, codesign gave none)")
            xml = b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict/></plist>'
    plistlib.loads(xml)                                  # must parse: ldid asserts on anything else
    return xml

def identifier(stock, blobs):
    cd = blobs.get(0)
    if cd and cd[:4] == b'\xfa\xde\x0c\x02':
        io = struct.unpack_from('>I', cd, 20)[0]
        return cd[io:cd.index(b'\0', io)].decode()
    return [l.split('=', 1)[1] for l in sh('codesign', '-dvvv', stock).splitlines() if l.startswith('Identifier=')][0]

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
    blobs = sig_blobs(stock)
    open(ents, 'wb').write(stock_entitlements(stock, blobs))
    # <records dir>/<name>.ents-add.plist: entitlements an ad-hoc copy needs that the Apple-signed (platform) original
    # got for free, e.g. lockdownd -> com.apple.springboard.CFUserNotification (SpringBoard's
    # FBServiceClientAuthenticator refuses the Trust alert otherwise: "Entitlement ... is required")
    add = osbcfg.rec(f'{name}.ents-add.plist')
    if os.path.exists(add):
        e = plistlib.load(open(ents, 'rb')); extra = plistlib.load(open(add, 'rb')); e.update(extra)
        plistlib.dump(e, open(ents, 'wb'), fmt=plistlib.FMT_XML)
        print(f"{name}: + entitlements {sorted(extra)}")
    ident = identifier(stock, blobs)
    sh('ldid', f'-S{ents}', f'-I{ident}', out)
    cd = [l.split('=', 1)[1] for l in sh('codesign', '-dvvv', *osbcfg.arm64e_arch(out), out).splitlines()
          if l.startswith('CDHash=')][0]
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
