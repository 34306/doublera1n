#!/usr/bin/env python3
"""Add an LC_LOAD_WEAK_DYLIB to a thin 64-bit Mach-O using the header slack before the first section.
   Usage: insert_dylib.py in out /path/to/lib.dylib     (re-sign afterwards: ldid -S<ents> -I<id>)"""
import struct, sys
src, dst, path = sys.argv[1:4]
d = bytearray(open(src, 'rb').read())
magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, _ = struct.unpack_from('<IiiIIIII', d, 0)
assert magic == 0xFEEDFACF, "thin 64-bit Mach-O only"
off = 32; first_sect = len(d)
for _ in range(ncmds):
    cmd, cs = struct.unpack_from('<II', d, off)
    if cmd in (0xC, 0x18, 0x80000018, 0x8000001F) and d[off + 24:off + cs].split(b'\0')[0] == path.encode():
        sys.exit(f"{path} already linked")
    if cmd == 0x19:                                   # LC_SEGMENT_64: sections' file offsets
        nsects = struct.unpack_from('<I', d, off + 64)[0]
        for s in range(nsects):
            so = off + 72 + 80 * s
            offset, = struct.unpack_from('<I', d, so + 48); size, = struct.unpack_from('<Q', d, so + 40)
            if offset and size: first_sect = min(first_sect, offset)
    off += cs
end = 32 + sizeofcmds
name = path.encode() + b'\0'
cmdsize = (24 + len(name) + 7) & ~7
if end + cmdsize > first_sect: sys.exit(f"no header slack: need {cmdsize}, have {first_sect - end}")
assert d[end:end + cmdsize] == bytes(cmdsize), "slack not zero"
lc = struct.pack('<IIIIII', 0x80000018, cmdsize, 24, 2, 0x10000, 0x10000) + name
d[end:end + cmdsize] = lc.ljust(cmdsize, b'\0')
struct.pack_into('<II', d, 16, ncmds + 1, sizeofcmds + cmdsize)
open(dst, 'wb').write(d)
print(f"LC_LOAD_WEAK_DYLIB {path} at 0x{end:x} ({cmdsize} B), slack left {first_sect - end - cmdsize}")
