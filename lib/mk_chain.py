#!/usr/bin/env python3
"""Build the iBSS -> iBEC -> bootx artifact set for the dual-boot setup ramdisk.
All images use the device's own APTicket; our patched iBoot bypasses AP-side Image4 validation.
Fourccs follow the restore-mode boot artifact layout."""
import os, shutil, subprocess, sys
from pyimg4 import IM4P, IM4M, IMG4, IM4PData, Compression

HERE = os.path.dirname(os.path.abspath(__file__))
JB = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import osbcfg
IPSW = osbcfg.IPSW
MODE = (sys.argv[1] if len(sys.argv) > 1 else 'install')
OUT = osbcfg.work('chain')
SETUP_IBSS = osbcfg.out('iBSS.setup.raw')
SETUP_IBEC = osbcfg.out('iBEC.setup.raw')
TICKET = IM4M(open(osbcfg.out('apticket.im4m'), 'rb').read())

FIRMWARE = [item for item in osbcfg.firmware() if item[1] != 'StaticTrustCache.img4']

def sign(im4p: IM4P, out: str):
    open(os.path.join(OUT, out), 'wb').write(IMG4(im4p=im4p, im4m=TICKET).output())
    print(f"  {out:24s} fourcc={im4p.fourcc} payload={len(im4p.payload.output().data)}")

def main():
    os.makedirs(OUT, exist_ok=True)
    for src, out, fourcc in FIRMWARE:
        p = IM4P(open(os.path.join(IPSW, src), 'rb').read())
        if fourcc: p.fourcc = fourcc
        sign(p, out)
    stale_tc = os.path.join(OUT, 'StaticTrustCache.img4')
    if os.path.exists(stale_tc):
        os.remove(stale_tc)
    if osbcfg.has('RestoreLogo') and os.path.isfile(osbcfg.ipsw('RestoreLogo')):
        logo = IM4P(open(osbcfg.ipsw('RestoreLogo'), 'rb').read())
        logo.fourcc = 'rlgo'
        sign(logo, 'RestoreLogo.img4')
    ibec = IM4P(open(osbcfg.ipsw('iBEC'), 'rb').read())
    ibec.payload = IM4PData(open(SETUP_IBEC, 'rb').read())
    ibec.payload.compress(Compression.LZFSE)
    sign(ibec, 'iBEC.img4')
    # DeviceTree without /defaults/content-protect (restore DeviceTree edits), fourcc rdtr
    dt = IM4P(open(osbcfg.ipsw('DeviceTree'), 'rb').read()); dt.payload.decompress()
    stock = os.path.join(OUT, 'DeviceTree.stock.raw'); patched = os.path.join(OUT, 'DeviceTree.patched.raw')
    open(stock, 'wb').write(dt.payload.output().data)
    r = subprocess.run([sys.executable, os.path.join(HERE, 'dt_patch.py'), stock, patched, '--del', '/defaults:content-protect'],
                       capture_output=True, text=True)
    if r.returncode: sys.exit(r.stdout + r.stderr)
    sign(IM4P(fourcc='rdtr', payload=open(patched, 'rb').read()), 'DeviceTree.img4')
    shutil.copy2(osbcfg.out('rsep.img4'), os.path.join(OUT, 'SEP.img4'))
    shutil.copy2(osbcfg.work(f'setuptc-{MODE}.img4'), os.path.join(OUT, 'RestoreTrustCache.img4'))
    shutil.copy2(osbcfg.work(f'setuprd-{MODE}.img4'), os.path.join(OUT, 'RestoreRamdisk.img4'))
    shutil.copy2(SETUP_IBSS, os.path.join(OUT, 'iBSS.raw'))
    print("SEP/RestoreTrustCache/RestoreRamdisk/iBSS.raw copied")

if __name__ == '__main__':
    main()
