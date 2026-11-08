#!/usr/bin/env python3
"""Rebuild the APTicket(s) rdsetup dumped to the console:  parse_ticket.py <serial log> <out dir>
Lines: 'TKT <off> <hex> <crc32>' (each 48-byte chunk printed twice; kernel output may interleave, so
only CRC-valid chunks are used) + '[rdsetup] TICKET dir=<hash> len=<n> sha384=<H> crc=<c>' header."""
import binascii, hashlib, os, re, sys
log = open(sys.argv[1], 'rb').read().decode('latin1')
outdir = sys.argv[2]; os.makedirs(outdir, exist_ok=True)
heads = re.findall(r'TICKET dir=([0-9A-Fa-f]{96}) len=(\d+) sha384=([0-9A-F]{96}) crc=([0-9a-f]{8})', log)
chunks = {}
for off, hx, crc in re.findall(r'TKT ([0-9a-f]{5}) ([0-9a-f]{2,96}) ([0-9a-f]{8})', log):
    b = bytes.fromhex(hx) if len(hx) % 2 == 0 else None
    if b and binascii.crc32(b) == int(crc, 16): chunks.setdefault(int(off, 16), b)
ok = 0
for d, n, sha, crc in heads[-1:] if heads else []:
    n = int(n); data = b''.join(chunks.get(o, b'') for o in range(0, n, 48))
    good = len(data) == n and hashlib.sha384(data).hexdigest().upper() == sha
    print(f"dir={d[:16]}.. len={n} chunks={len(chunks)} sha384 ok={good} (dir name match: {sha == d.upper()})")
    if good:
        p = os.path.join(outdir, f"apticket-{d[:16].lower()}.der"); open(p, 'wb').write(data); print("wrote", p); ok = 1
    else:
        print("missing offsets:", [hex(o) for o in range(0, n, 48) if o not in chunks][:20])
sys.exit(0 if ok else 1)
