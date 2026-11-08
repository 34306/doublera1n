#!/usr/bin/env python3
"""Statically patched kernel + TXM for the bootx chain (no iBoot KPF hooks needed).
Kernel: restore plan without the debugger/identity records (patches/kernel-restore-nodebugger.json)
        + vm-fault cs bypass  -> AMFI launch constraints / trust cache / post-validation return success.
TXM:    patches/txm-cs-only.json.
Apple's im4p is kept (fourcc changed to rkrn, PAYP properties + description kept, LZFSE),
only the payload is replaced; every record's original bytes are checked by kpf.records_to_words."""
import os, struct, sys
from pyimg4 import IM4P, IM4M, IMG4, IM4PData, Compression

HERE = os.path.dirname(os.path.abspath(__file__))
JB = os.path.dirname(HERE)
sys.path.insert(0, JB); sys.path.insert(0, HERE)
import kpf, osbcfg

IPSW = osbcfg.IPSW
OUT = osbcfg.work('chain')
TICKET = IM4M(open(osbcfg.out('apticket.im4m'), 'rb').read())
P = osbcfg.patch

IMAGES = [  # (ipsw im4p, output, fourcc or None, record files)
    (osbcfg.comp('KernelCache'), 'Kernelcache.img4', 'rkrn',
     [P('kernel-restore-nodebugger.json'), P('kernel-vm-fault-cs-bypass.json')]),
    (osbcfg.comp('Ap,TrustedExecutionMonitor'), 'TXM.img4', None, [P('txm-cs-only.json')]),
]

def main():
    os.makedirs(OUT, exist_ok=True)
    for src, out, fourcc, jsons in IMAGES:
        p = IM4P(open(os.path.join(IPSW, src), 'rb').read())
        p.payload.decompress()
        raw = bytearray(p.payload.output().data)
        recs = kpf.load_records(jsons, exclude_prefixes=("kernel.identity",))
        words = kpf.records_to_words(bytes(raw), recs)
        for off, o, n in words:
            assert struct.unpack_from('<I', raw, off)[0] == o
            struct.pack_into('<I', raw, off, n)
        open(os.path.join(OUT, out.replace('.img4', '.patched.raw')), 'wb').write(raw)
        p.payload = IM4PData(bytes(raw))
        p.payload.compress(Compression.LZFSE)
        if fourcc: p.fourcc = fourcc
        open(os.path.join(OUT, out), 'wb').write(IMG4(im4p=p, im4m=TICKET).output())
        # round trip
        chk = IMG4(open(os.path.join(OUT, out), 'rb').read()).im4p
        props = [str(x) for x in chk.properties]
        chk.payload.decompress()
        assert chk.payload.output().data == bytes(raw)
        print(f"{out:18s} fourcc={chk.fourcc} desc={chk.description} records={len(recs)} words={len(words)} "
              f"props={len(props)} ids: {' '.join(r['id'] for r in recs)}")

if __name__ == '__main__':
    main()
