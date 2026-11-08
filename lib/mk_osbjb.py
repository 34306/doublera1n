#!/usr/bin/env python3
"""OS B + jailbreak userland ("osbjb"): the mk_osb.py artifacts plus
  * jb ramdisk (rdsk): /sbin/launchd stub -> /usr/lib/dyld = jbinit (static PID 1), /jbin/jbloader,
    /jbin/bootstrap.tar.gz (Procursus rootless), /jbin/authorized_keys
      jbinit: union-mount stock System ro over "/", fork a child that runs jbloader once DataB is on
      /private/var (bootstrap -> /var/jb, sshd :22), parent execs the real /sbin/launchd
  * kernel = boot-jit plan + kernel-ramdisk.json (MNT_UNION / rootfs / 'rd'->'jb' boot-arg)
    + kernel-osb.json (SEP-less OS B), see kpatchfind.py
  * iBEC boot-args "jb=md0 ..." (XNU and APFS container_rootmount parse 'jb' after the two rename patches;
    other kexts and launchd - which only looks for the literal "rd=md0" - see a normal boot)
  * rtsc trust cache = System static TC (v2) + cdhashes of the ramdisk binaries and cache-override daemons
Everything signed with the installed APTicket (mk_osb.TICKET). Nothing is written to the device here."""
import os, plistlib, shutil, struct, subprocess, sys
from pyimg4 import IM4P, IMG4, IM4PData, Compression

HERE = os.path.dirname(os.path.abspath(__file__))
JB = os.path.dirname(HERE)
sys.path.insert(0, HERE); sys.path.insert(0, JB)
import mk_osb, kpf, osbcfg

OSB = osbcfg.work('osb')
OUT = osbcfg.work('osbjb')
B = osbcfg.work('jbrd')                                   # intermediate dir
# device binaries of the boot ramdisk: payload/boot (rebuilt from src/ by src/build.sh and src/launchctl/build.sh)
PREBUILT = os.environ.get('OSB_PREBUILT') or os.path.join(JB, 'payload/boot')
BOOTARGS = "jb=md0 -v serial=3 debug=0x2014e launchd_unsecure_cache=1 wdt=-1"
SSHKEY = osbcfg.out('osb_ssh/id_ed25519')
TOOLS = ('launchctl', 'bpexec', 'lsimg', 'hactpoke', 'maactivate', 'mobileactivationd')
# mobileactivationd with its userland patch records applied to the stock binary (mkdaemon.py), original ents/id
MOBILEACTIVATIOND = osbcfg.work('daemons/mobileactivationd')
PREBUILT_FILES = ('dyld', 'launchd', 'jbloader', 'hacthook.dylib', 'launchctl', 'bpexec', 'lsimg',
                  'hactpoke', 'maactivate', 'obhook.dylib', 'bootstrap.tar.gz')

def sign(p, out):
    open(os.path.join(OUT, out), 'wb').write(IMG4(im4p=p, im4m=mk_osb.TICKET).output())

def sh(*a, **k):
    r = subprocess.run(a, capture_output=True, text=True, **k)
    if r.returncode: sys.exit(f"!! {' '.join(a)}\n{r.stdout}{r.stderr}")
    return r.stdout + r.stderr

def cdhash(path):
    for l in sh('codesign', '-dvvv', path).splitlines():
        if l.startswith('CDHash='): return bytes.fromhex(l.split('=', 1)[1])
    sys.exit(f"no CDHash for {path}")

def build_binaries():
    os.makedirs(B, exist_ok=True)
    for n in PREBUILT_FILES:
        if not os.path.exists(os.path.join(PREBUILT, n)): sys.exit(f"missing {PREBUILT}/{n} (src/build.sh rebuilds it)")
        shutil.copy2(os.path.join(PREBUILT, n), os.path.join(B, n))
    if not os.path.exists(MOBILEACTIVATIOND): sys.exit(f"missing {MOBILEACTIVATIOND} (built from the rootfs during install)")
    shutil.copy2(MOBILEACTIVATIOND, os.path.join(B, 'mobileactivationd'))
    return {n: cdhash(os.path.join(B, n)) for n in TOOLS + ('dyld', 'launchd', 'jbloader', 'hacthook.dylib', 'obhook.dylib')}

# launchd job cache override (jbinit bindfs-mounts /jbin/xpc over /System/Library/xpc; launchd_cache_loader honours
# launchd_unsecure_cache= in the boot-args). Jobs edited here start correctly from the very first launch - no swap
# race: stock securityd must never run on OS B (it cannot decrypt obkeychain items and DELETES them as corrupt,
# e.g. the Wi-Fi password queried by wifid in the first seconds after boot).
CACHE_PROGRAMS = {  # stock program -> (work file, ramdisk path); each starts patched from its first launch
    '/usr/libexec/securityd': ('daemons/securityd', '/cores/daemons/securityd'),
    '/usr/libexec/lockdownd': ('daemons/lockdownd', '/cores/daemons/lockdownd'),
    '/usr/libexec/mobileactivationd': ('daemons/mobileactivationd', '/cores/daemons/mobileactivationd'),
    '/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd':
        ('daemons/coreauthd', '/cores/daemons/coreauthd'),   # stock one segfaults in the SEP ratchet parser at boot
    '/System/Library/Frameworks/CryptoTokenKit.framework/ctkd': ('daemons/ctkd', '/cores/daemons/ctkd'),
}
CACHE_BINS = {}
CACHE_STRIP = {'com.apple.watchdogd': ('KeepAlive', 'LaunchEvents', '_PanicOnCrash')}   # crash-loop -> panic on OS B

def build_cache(root):
    src = os.path.join(osbcfg.ROOTFS, 'System/Library/xpc')
    if not os.path.exists(os.path.join(src, 'launchd.plist')):
        print(f"  !! no {src}/launchd.plist - launchd cache override skipped"); return [], {}
    dst = os.path.join(root, 'jbin/xpc'); shutil.copytree(src, dst)
    cache = plistlib.load(open(os.path.join(src, 'launchd.plist'), 'rb'))
    labels, bins = [], {}
    for j in cache['LaunchDaemons'].values():
        prog = j.get('Program') or (j.get('ProgramArguments') or [None])[0]
        if prog in CACHE_PROGRAMS:
            wf, path = CACHE_PROGRAMS[prog]
            if not os.path.exists(osbcfg.work(wf)):
                print(f"  !! {osbcfg.work(wf)} missing - {j['Label']} keeps the stock program"); continue
            if 'Program' in j: j['Program'] = path
            if 'ProgramArguments' in j: j['ProgramArguments'] = [path] + list(j['ProgramArguments'][1:])
            d = os.path.join(root, 'jbin', os.path.relpath(path, '/cores'))
            os.makedirs(os.path.dirname(d), exist_ok=True); shutil.copy2(osbcfg.work(wf), d); os.chmod(d, 0o755)
            bins[os.path.relpath(path, '/cores')] = d
            labels.append(j['Label'])
        if j.get('Label') in CACHE_STRIP:
            for k in CACHE_STRIP[j['Label']]: j.pop(k, None)
            labels.append(j['Label'])
    os.chmod(os.path.join(dst, 'launchd.plist'), 0o644)
    plistlib.dump(cache, open(os.path.join(dst, 'launchd.plist'), 'wb'), fmt=plistlib.FMT_BINARY)
    assert plistlib.load(open(os.path.join(dst, 'launchd.plist'), 'rb')) == cache
    open(os.path.join(root, 'jbin/osb-cache-jobs.txt'), 'w').write(''.join(l + '\n' for l in labels))
    print(f"  launchd cache    override jobs: {', '.join(labels)}")
    return labels, bins

def build_ramdisk():
    root = os.path.join(B, 'root2'); shutil.rmtree(root, ignore_errors=True)
    for d in ('dev', 'sbin', 'usr/lib', 'jbin', 'private', 'var', 'tmp', 'System', 'cores'):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    shutil.copy2(os.path.join(B, 'dyld'), os.path.join(root, 'usr/lib/dyld'))
    shutil.copy2(os.path.join(B, 'launchd'), os.path.join(root, 'sbin/launchd'))
    shutil.copy2(os.path.join(B, 'jbloader'), os.path.join(root, 'jbin/jbloader'))
    shutil.copy2(os.path.join(B, 'hacthook.dylib'), os.path.join(root, 'jbin/hacthook.dylib'))
    shutil.copy2(os.path.join(PREBUILT, 'com.apple.mobileactivationd.plist'), os.path.join(root, 'jbin/com.apple.mobileactivationd.plist'))
    shutil.copy2(os.path.join(B, 'obhook.dylib'), os.path.join(root, 'jbin/obhook.dylib'))   # -> /cores/obhook.dylib (bindfs)
    for n in TOOLS: shutil.copy2(os.path.join(B, n), os.path.join(root, 'jbin', n)); os.chmod(os.path.join(root, 'jbin', n), 0o755)
    shutil.copy2(os.path.join(B, 'bootstrap.tar.gz'), os.path.join(root, 'jbin/bootstrap.tar.gz'))
    shutil.copy2(SSHKEY + '.pub', os.path.join(root, 'jbin/authorized_keys'))
    for p in ('usr/lib/dyld', 'sbin/launchd', 'jbin/jbloader'): os.chmod(os.path.join(root, p), 0o755)
    global CACHE_BINS
    _, CACHE_BINS = build_cache(root)
    dmg = os.path.join(B, 'jbrd2.dmg')
    if os.path.exists(dmg): os.remove(dmg)
    sh('hdiutil', 'create', '-size', '96m', '-fs', 'APFS', '-layout', 'NONE', '-volname', 'jbrd',
       '-srcfolder', root, '-format', 'UDRW', dmg)
    d = open(dmg, 'rb').read()
    assert d.find(b'NXSB') == 0x20, "not a raw APFS container"
    return d

def main():
    if not os.path.exists(SSHKEY):
        os.makedirs(os.path.dirname(SSHKEY), exist_ok=True)
        sh('ssh-keygen', '-t', 'ed25519', '-N', '', '-C', 'dualboot-osb', '-f', SSHKEY)
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OSB):
        if f.endswith('.img4') or f == 'iBSS.raw': shutil.copy2(os.path.join(OSB, f), os.path.join(OUT, f))
    hashes = build_binaries()
    rd = build_ramdisk()
    for n, path in CACHE_BINS.items(): hashes[n] = cdhash(path)
    for n, h in hashes.items(): print(f"  {n:9s} cdhash {h.hex()}")
    # rtsc = System TC v2 + ours
    tc = IM4P(open(osbcfg.ipsw('StaticTrustCache'), 'rb').read()).payload.output().data
    ver, = struct.unpack_from('<I', tc, 0); n, = struct.unpack_from('<I', tc, 20); assert ver == 2 and len(tc) == 24 + 24 * n
    ents = [tc[24 + 24 * i:24 + 24 * (i + 1)] for i in range(n)]
    for h in hashes.values():
        e = h + bytes([2, 0, 0, 0])
        if e not in ents: ents.append(e)
    ents.sort()
    newtc = struct.pack('<I', 2) + tc[4:20] + struct.pack('<I', len(ents)) + b''.join(ents)
    sign(IM4P(fourcc='rtsc', payload=newtc), 'RestoreTrustCache.img4')
    print(f"  RestoreTrustCache  rtsc v2 entries {n} -> {len(ents)}")
    # ramdisk (built above)
    sign(IM4P(fourcc='rdsk', payload=rd), 'RestoreRamdisk.img4')
    print(f"  RestoreRamdisk     rdsk {len(rd)} bytes")
    # kernel = boot-jit + ramdisk records
    p = IM4P(open(osbcfg.ipsw('KernelCache'), 'rb').read()); p.payload.decompress()
    raw = bytearray(p.payload.output().data)
    recs = kpf.load_records([osbcfg.rec('kernel-boot-jit.json'), osbcfg.patch('kernel-ramdisk.json'),
                             osbcfg.patch('kernel-osb.json')],
                            exclude_prefixes=("kernel.identity",))
    words = kpf.records_to_words(bytes(raw), recs)
    for off, o, nw in words: struct.pack_into('<I', raw, off, nw)
    p.payload = IM4PData(bytes(raw)); p.payload.compress(Compression.LZFSE); p.fourcc = 'rkrn'
    sign(p, 'Kernelcache.img4')
    print(f"  Kernelcache        rkrn records {len(recs)} words {len(words)}")
    # iBEC with jb=md0
    sh(sys.executable, os.path.join(HERE, 'patch_iboot.py'), '--no-fsboot', f'--boot-args={BOOTARGS}',
       stock_ibec(), osbcfg.out('iBoot.osbjb.raw'))
    ibec = IM4P(open(osbcfg.ipsw('iBEC'), 'rb').read())
    ib = open(osbcfg.out('iBoot.osbjb.raw'), 'rb').read()
    ibec.payload = IM4PData(ib); ibec.payload.compress(Compression.LZFSE)
    sign(ibec, 'iBEC.img4')
    print(f"  iBEC               boot-args {ib[ib.find(b'jb=md0'):].split(bytes(1))[0].decode()!r}")

def stock_ibec():
    path = os.path.join(B, 'iBEC.stock.raw')
    if not os.path.exists(path):
        p = IM4P(open(osbcfg.ipsw('iBEC'), 'rb').read())
        p.payload.decompress(); open(path, 'wb').write(p.payload.output().data)
    return path

if __name__ == '__main__':
    main()
