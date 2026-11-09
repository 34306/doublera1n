#!/usr/bin/env python3
"""OS B (stock sealed System + DataB as /private/var) normal-boot artifact set:
  iBSS.raw   minimal patched iBoot (validate + boot-args)            - same as the setup chain
  iBEC.img4  Apple iBEC im4p, payload = $OSB_OUT/iBoot.osb.raw (validate + normal boot-args + serial=3)
  firmware   passthrough (ANE AOP AVE SPTM GFX ISP PMP SIO WCH), signed from the IPSW
  RestoreTrustCache.img4  the System static trust cache, re-tagged 'rtsc'
  TXM.img4   txm boot-permissive plan
  Kernel     boot-jit plan (SEP-less: aks/sep/credential-manager/sandbox/...) minus kernel.identity
  DeviceTree `normal` edit list + OS B edits:
             /filesystems/fstab/data-vol vol.fs_role 0x40 -> 0  (DT_get_fstab_entries then picks the only
             role-0 volume of the boot container = DataB)
             xart/update/hardware volumes (shared with the stock OS) mounted read-only; baseband stays rw
  SEP.img4   real rsep (iBoot TZ setup needs it loaded; the kernel no longer talks to it)
Nothing here writes to the device; boot_chain.py --osb sends it."""
import json, os, shutil, struct, subprocess, sys
from pyimg4 import IM4P, IM4M, IMG4, IM4PData, Compression

HERE = os.path.dirname(os.path.abspath(__file__))
JB = os.path.dirname(HERE)
sys.path.insert(0, JB); sys.path.insert(0, HERE)
import kpf, osbcfg

IPSW = osbcfg.IPSW
OUT = osbcfg.work('osb')
REC = osbcfg.REC
# Must be the APTicket INSTALLED on the device (Preboot/<BootManifestHash>/System/Library/Caches/apticket.der):
# iBoot publishes sha384(IM4M) as /chosen/boot-manifest-hash and seputil/FUD look up Preboot/<that hash>/...
TICKET_PATH = osbcfg.TICKET
TICKET = IM4M(open(TICKET_PATH, 'rb').read())
PASSTHROUGH = ['ANE', 'AOP', 'AVE', 'SPTM', 'GFX', 'ISP', 'PMP', 'SIO', 'WCH']
import dt_patch
# shared with lib/precheck.py; the 2nd iOS (OSB_OS2=1, developing feature) points system-vol/data-vol at
# OS2System/OS2Data by their APFS roles instead
DT_OPS = dt_patch.OS2_OPS if osbcfg.OS2 else dt_patch.OSB_OPS

def sign(p, out):
    open(os.path.join(OUT, out), 'wb').write(IMG4(im4p=p, im4m=TICKET).output())

def patched(src, jsons, out, fourcc=None, exclude=("kernel.identity",)):
    p = IM4P(open(os.path.join(IPSW, src), 'rb').read())
    p.payload.decompress()
    raw = bytearray(p.payload.output().data)
    recs = kpf.load_records(jsons, exclude_prefixes=exclude)
    words = kpf.records_to_words(bytes(raw), recs)          # checks every original byte
    for off, o, n in words:
        assert struct.unpack_from('<I', raw, off)[0] == o
        struct.pack_into('<I', raw, off, n)
    open(os.path.join(OUT, out.replace('.img4', '.patched.raw')), 'wb').write(raw)
    p.payload = IM4PData(bytes(raw)); p.payload.compress(Compression.LZFSE)
    if fourcc: p.fourcc = fourcc
    sign(p, out)
    chk = IMG4(open(os.path.join(OUT, out), 'rb').read()).im4p
    chk.payload.decompress(); assert chk.payload.output().data == bytes(raw)
    print(f"  {out:18s} fourcc={chk.fourcc} records={len(recs)} words={len(words)} props={len(list(chk.properties))}")

def main():
    os.makedirs(OUT, exist_ok=True)
    src = {out[:-5]: (path, fcc) for path, out, fcc in osbcfg.firmware()}   # same sources/fourccs as the setup chain
    for n in PASSTHROUGH:
        if n not in src:                      # not in this board's manifest (WCH on iPads)
            continue
        path, fcc = src[n]
        fw = IM4P(open(os.path.join(IPSW, path), 'rb').read())
        if fcc: fw.fourcc = fcc
        sign(fw, n + '.img4')
    shutil.copy2(osbcfg.out('rsep.img4'), os.path.join(OUT, 'SEP.img4'))
    shutil.copy2(osbcfg.out('iBoot.min.raw'), os.path.join(OUT, 'iBSS.raw'))
    print("  passthrough firmware, SEP, iBSS.raw copied")
    # System (static) trust cache sent as 'rtsc': otherwise iBoot's boot_kernel tries to load a 'trst' cache
    # itself, which fails in remote boot and clashes with an uploaded 'trst'. An uploaded rtsc makes iBoot skip
    # that step.
    tc = IM4P(open(osbcfg.ipsw('StaticTrustCache'), 'rb').read())
    tc.fourcc = 'rtsc'
    sign(tc, 'RestoreTrustCache.img4')
    if os.path.exists(os.path.join(OUT, 'StaticTrustCache.img4')): os.remove(os.path.join(OUT, 'StaticTrustCache.img4'))
    print("  RestoreTrustCache.img4 = System static trust cache, fourcc rtsc")
    ibec = IM4P(open(osbcfg.ipsw('iBEC'), 'rb').read())
    raw = open(osbcfg.out('iBoot.osb.raw'), 'rb').read()
    ibec.payload = IM4PData(raw); ibec.payload.compress(Compression.LZFSE)
    sign(ibec, 'iBEC.img4')
    chk = IMG4(open(os.path.join(OUT, 'iBEC.img4'), 'rb').read()).im4p; chk.payload.decompress()
    assert chk.payload.output().data == raw and chk.fourcc == 'ibec'
    print(f"  iBEC.img4          fourcc=ibec desc={chk.description} boot-args={raw[raw.find(b'-v serial'):].split(bytes(1))[0].decode()!r}")
    patched(osbcfg.comp('KernelCache'), [os.path.join(REC, 'kernel-boot-jit.json')], 'Kernelcache.img4', 'rkrn')
    patched(osbcfg.comp('Ap,TrustedExecutionMonitor'), [os.path.join(REC, 'txm-boot-permissive.json')], 'TXM.img4')
    # DeviceTree
    p = IM4P(open(osbcfg.ipsw('DeviceTree'), 'rb').read())
    p.payload.decompress()
    src = os.path.join(OUT, 'DeviceTree.stock.raw'); dst = os.path.join(OUT, 'DeviceTree.patched.raw')
    open(src, 'wb').write(p.payload.output().data)
    r = subprocess.run([sys.executable, os.path.join(HERE, 'dt_patch.py'), src, dst] + DT_OPS, capture_output=True, text=True)
    print('\n'.join('    ' + l for l in r.stdout.strip().splitlines()))
    if r.returncode: sys.exit(r.stderr)
    sign(IM4P(fourcc='rdtr', payload=open(dst, 'rb').read()), 'DeviceTree.img4')
    print(f"  DeviceTree.img4    fourcc=rdtr")

if __name__ == '__main__':
    main()
