#!/usr/bin/env python3
"""mkimg4.py in.im4p im4m out.img4 [--tag XXXX] [--raw payload.bin --desc DESC --lzfse]
Wrap an IM4P (optionally re-tagged, or rebuilt from a raw payload) with an IM4M into an IMG4.
When rebuilding from raw, the PAYP (kernelcache/TXM properties) of the original im4p is preserved."""
import argparse
from pyimg4 import IM4P, IM4M, IMG4, Compression

ap = argparse.ArgumentParser()
ap.add_argument("im4p"); ap.add_argument("im4m"); ap.add_argument("out")
ap.add_argument("--tag"); ap.add_argument("--raw"); ap.add_argument("--lzfse", action="store_true")
a = ap.parse_args()

orig = IM4P(open(a.im4p, "rb").read())
if a.raw:
    p = IM4P(fourcc=orig.fourcc, description=orig.description, payload=open(a.raw, "rb").read())
    if a.lzfse: p.payload.compress(Compression.LZFSE)
    if orig.properties: p.properties = orig.properties
else:
    p = orig
if a.tag: p.fourcc = a.tag
img4 = IMG4(im4p=p, im4m=IM4M(open(a.im4m, "rb").read()))
open(a.out, "wb").write(img4.output())
print(f"{a.out}: fourcc={p.fourcc} size={len(img4.output())}")
