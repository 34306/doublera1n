#!/usr/bin/env python3
"""Mark imports weak in a thin arm64 Mach-O that uses LC_DYLD_CHAINED_FIXUPS (missing symbol -> NULL
instead of dyld refusing to load).  Usage: weakimport.py in out _sym1 [_sym2 ...]   (re-sign afterwards)"""
import struct, sys
src, dst, *syms = sys.argv[1:]
d = bytearray(open(src, 'rb').read())
assert struct.unpack_from('<I', d, 0)[0] == 0xFEEDFACF, "thin 64-bit Mach-O only"
ncmds = struct.unpack_from('<I', d, 16)[0]; off = 32; cf = None
for _ in range(ncmds):
    cmd, cs = struct.unpack_from('<II', d, off)
    if cmd == 0x80000034: cf = struct.unpack_from('<II', d, off + 8)
    off += cs
assert cf, "no LC_DYLD_CHAINED_FIXUPS"
base = cf[0]
ver, starts, imports, symbols, count, ifmt, sfmt = struct.unpack_from('<7I', d, base)
assert sfmt == 0, "compressed symbol names unsupported"
size = {1: 4, 2: 8, 3: 16}[ifmt]
done = set()
for i in range(count):
    p = base + imports + i * size
    if ifmt in (1, 2):
        v = struct.unpack_from('<I', d, p)[0]; name_off = v >> 9; weak_bit = 1 << 8
    else:
        v = struct.unpack_from('<Q', d, p)[0]; name_off = v >> 32; weak_bit = 1 << 16
    n = base + symbols + name_off
    name = d[n:d.index(b'\0', n)].decode()
    if name in syms:
        v |= weak_bit
        struct.pack_into('<I' if ifmt in (1, 2) else '<Q', d, p, v)
        done.add(name); print(f"import #{i} {name}: weak")
missing = set(syms) - done
if missing: sys.exit(f"not found: {missing}")
open(dst, 'wb').write(d)
