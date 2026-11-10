#!/usr/bin/env python3
import os, shutil, struct, subprocess, sys, tempfile
from pyimg4 import IM4P, IM4M, IMG4

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import osbcfg

ROOT = os.path.dirname(HERE)
RDSETUP = os.environ.get('OSB_RDSETUP') or os.path.join(ROOT, 'payload/setup/rdsetup')
USBRELAY = os.path.join(ROOT, 'payload/setup/rdsetup_usbrelay')

def sh(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"!! {' '.join(a)}\n{r.stdout}{r.stderr}")
    return r.stdout + r.stderr

def cdhash(path):
    for l in sh('codesign', '-dvvv', *osbcfg.arm64e_arch(path), path).splitlines():
        if l.startswith('CDHash='):
            return bytes.fromhex(l.split('=', 1)[1])
    sys.exit(f"no CDHash for {path}")


def stage_payload(mnt, mode):
    if mode not in ('install', 'remove'):
        raise ValueError(f'unknown setup mode: {mode}')
    dst = os.path.join(mnt, 'usr/local/bin/restored_external')
    child = os.path.join(mnt, 'usr/local/bin/rdsetup')
    if not os.path.isfile(dst):
        raise ValueError('restore ramdisk has no usr/local/bin/restored_external')
    if not os.path.isfile(USBRELAY):
        raise ValueError(f'USB setup relay missing: {USBRELAY}')
    shutil.copyfile(RDSETUP, child)
    os.chmod(child, 0o755)
    shutil.copyfile(USBRELAY, dst)
    os.chmod(dst, 0o755)
    config = os.path.join(mnt, 'usr/local/share/dualboot')
    os.makedirs(config, exist_ok=True)
    with open(os.path.join(config, 'mode'), 'w') as stream:
        stream.write(mode + '\n')
    return RDSETUP, USBRELAY


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'install'
    assert mode in ('install', 'remove')
    ticket = IM4M(open(osbcfg.out('apticket.im4m'), 'rb').read())
    os.makedirs(osbcfg.WORK, exist_ok=True)
    # ramdisk payload (raw APFS image)
    rd = IM4P(open(osbcfg.ipsw('RestoreRamDisk'), 'rb').read())
    try:
        rd.payload.decompress()
    except Exception:
        pass                                  # restore ramdisks are usually stored uncompressed
    raw = osbcfg.work(f'setuprd-{mode}.raw')
    open(raw, 'wb').write(rd.payload.output().data)
    mnt = tempfile.mkdtemp(prefix='dualboot-rd-')
    sh('hdiutil', 'attach', '-nobrowse', '-owners', 'off', '-noverify', '-imagekey',
       'diskimage-class=CRawDiskImage', '-mountpoint', mnt, raw)
    try:
        sources = stage_payload(mnt, mode)
        subprocess.run(['sync'])
    finally:
        sh('hdiutil', 'detach', mnt)
        os.rmdir(mnt)
    data = open(raw, 'rb').read()
    # trust cache v1: version, uuid[16], count, entries of cdhash[20] + hash_type + flags
    tc = IM4P(open(osbcfg.ipsw('RestoreTrustCache'), 'rb').read()).payload.output().data
    ver, = struct.unpack_from('<I', tc, 0); n, = struct.unpack_from('<I', tc, 20)
    assert ver == 1 and len(tc) == 24 + 22 * n, f"unexpected trust cache v{ver} len {len(tc)}"
    ents = [tc[24 + 22 * i:24 + 22 * (i + 1)] for i in range(n)]
    for path in sources:
        e = cdhash(path) + b'\x02\x00'
        if e not in ents:
            ents.append(e)
    ents.sort()
    newtc = tc[:20] + struct.pack('<I', len(ents)) + b''.join(ents)
    open(osbcfg.work(f'setuptc-{mode}.img4'), 'wb').write(
        IMG4(im4p=IM4P(fourcc='rtsc', payload=newtc), im4m=ticket).output())
    open(osbcfg.work(f'setuprd-{mode}.img4'), 'wb').write(
        IMG4(im4p=IM4P(fourcc='rdsk', payload=data), im4m=ticket).output())
    os.remove(raw)
    print(f"  setup ramdisk ({mode}): rdsk {len(data)} bytes, rtsc {n} -> {len(ents)} entries")

if __name__ == '__main__':
    main()
