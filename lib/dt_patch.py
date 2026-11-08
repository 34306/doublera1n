#!/usr/bin/env python3
"""Minimal Apple flattened DeviceTree editor (property set/remove by node path) and the DeviceTree edit lists
of the setup chain and of OS B.
node := u32 nprops, u32 nchildren, prop*, node*
prop := char name[32], u32 len (bit31 = placeholder flag), value[len] padded to 4
Usage: dt_patch.py in.raw out.raw [--del /node/path:prop]... [--set /node/path:prop=u32]...
A parse/serialize round trip is checked to be byte-identical before edits are applied."""
import struct, sys

# Edit lists shared by the builders and lib/precheck.py (one source of truth)
FSTAB = '/filesystems/fstab'
SETUP_OPS = ['--del', '/defaults:content-protect']                 # setup ramdisk chain (mk_chain.py)
OSB_OPS = [                                                         # OS B (mk_osb.py)
    # `normal` edit list
    '--del', '/defaults:content-protect',
    '--set', '/defaults:no-effaceable-storage=1',
    '--set', '/product:boot-ios-diagnostics=1',
    '--set', '/chosen:ephemeral-storage=1',
    # OS B
    '--set', f'{FSTAB}/data-vol:vol.fs_role=0',
    '--setstr', f'{FSTAB}/xart-vol:vol.fs_type=ro',
    '--setstr', f'{FSTAB}/update-vol:vol.fs_type=ro',
    # baseband-vol stays rw: CommCenter/BBFS need to write the modem's storage
    '--setstr', f'{FSTAB}/hardware-vol:vol.fs_type=ro',
]

def parse(d, o):
    nprops, nchild = struct.unpack_from('<II', d, o); o += 8
    props = []
    for _ in range(nprops):
        name = d[o:o + 32]; ln, = struct.unpack_from('<I', d, o + 32); o += 36
        n = ln & 0x7FFFFFFF
        val = d[o:o + ((n + 3) & ~3)]; o += (n + 3) & ~3
        props.append([name, ln, val])
    kids = []
    for _ in range(nchild):
        k, o = parse(d, o); kids.append(k)
    return [props, kids], o

def ser(node):
    props, kids = node
    out = struct.pack('<II', len(props), len(kids))
    for name, ln, val in props:
        out += name + struct.pack('<I', ln) + val
    for k in kids: out += ser(k)
    return out

def pname(p): return p[0].split(b'\0')[0].decode()
def nname(node):
    for p in node[0]:
        if pname(p) == 'name': return p[2][:p[1] & 0x7FFFFFFF].split(b'\0')[0].decode()
    return ''

def find(root, path):
    node = root
    for part in [x for x in path.split('/') if x]:
        node = next((k for k in node[1] if nname(k) == part), None)
        if node is None: raise SystemExit(f"node {path} not found")
    return node

def main():
    src, dst, *ops = sys.argv[1:]
    d = open(src, 'rb').read()
    root, end = parse(d, 0)
    assert ser(root) == d[:end], "round trip mismatch"
    i = 0
    while i < len(ops):
        op, arg = ops[i], ops[i + 1]; i += 2
        path, rest = arg.split(':', 1)
        node = find(root, path)
        if op == '--del':
            before = len(node[0]); node[0] = [p for p in node[0] if pname(p) != rest]
            print(f"del {path}:{rest} ({'removed' if len(node[0]) < before else 'absent'})")
        elif op == '--setstr':   # existing string property, NUL-terminated, length may change
            prop, val = rest.split('=', 1); raw = val.encode() + b'\0'
            ex = [p for p in node[0] if pname(p) == prop]
            if len(ex) != 1: raise SystemExit(f"{path}:{prop} not found")
            ex[0][1] = (ex[0][1] & 0x80000000) | len(raw); ex[0][2] = raw.ljust((len(raw) + 3) & ~3, b'\0')
            print(f"setstr {path}:{prop}={val!r}")
        elif op == '--set':
            prop, val = rest.split('=', 1); v = struct.pack('<I', int(val, 0))
            ex = [p for p in node[0] if pname(p) == prop]
            if ex: ex[0][1] = 4; ex[0][2] = v; print(f"set {path}:{prop}={val} (updated)")
            else: node[0].append([prop.encode().ljust(32, b'\0'), 4, v]); print(f"set {path}:{prop}={val} (added)")
    out = ser(root) + d[end:]
    root2, _ = parse(out, 0)
    open(dst, 'wb').write(out)
    print(f"{src} -> {dst}: {len(d)} -> {len(out)} bytes")

if __name__ == '__main__':
    main()
