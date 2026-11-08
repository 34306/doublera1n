#!/usr/bin/env python3
"""Build payload/pkgs/Sileo.app.tar from the upstream Sileo 2.5.1 rootless deb (payload/pkgs/sileo.deb).

Re-signing and the chown edit:
  * "mobile:mobile" -> "000501:000501": DependencyResolverAccelerator.init chowns sileolists through CommandPath.group,
    and the Procursus passwd on OS B has no "mobile" user; 000501 is uid/gid 501 padded to the same length.
  * the shipped binary carries no usable signature; it is re-signed ad-hoc with 8 entitlements (the full upstream
    set includes a restricted key AMFI kills ad-hoc binaries for), giveMeRoot keeps setuid root.
dualboot's own edit, so Sileo shows "palera1n • Rootless" with its Procursus /var/jb paths:
  Sileo's Jailbreak.init() (https://github.com/Sileo/Sileo, Sileo/Backend/Root Wrapper/Jailbreak.swift) only tests
  the palera1n case (/cores/jbloader, then /var/jb/.procursus_strapped -> .palera1n_rootless) when
  NXGetLocalArchInfo()->name != "arm64e". The Swift small-string literal of `arch() == "arm64e"` (its fast 8-byte
  compare and the _stringCompareWithSmolCheck call) becomes "arm64x", so arm64e is false on A12+ and the palera1n
  case matches: OS B always has /cores/jbloader (jbinit bindfs /jbin -> /cores) and nothing that bakera1n,
  palera1n-legacy or checkra1n look for. Both edit sites are found by instruction pattern, not by offset.

usage: patch_sileo.py [--deb payload/pkgs/sileo.deb] [--out payload/pkgs/Sileo.app.tar]
"""
import argparse, hashlib, io, lzma, os, plistlib, shutil, struct, subprocess, sys, tarfile, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SILEO_SHA = '8e3c90e5a7d32f4ca207a0ac30d3cfa8a13dca86a2b4e11cb3f9e5c68d7bc97a'   # org.coolstar.sileo_2.5.1_iphoneos-arm64.deb
APP_PREFIX = './var/jb/Applications/Sileo.app'
BUNDLE_ID = 'org.coolstar.SileoStore'
ARM64E = (0x7261, 0x366D, 0x6534)          # "ar" "m6" "4e" as MOVZ/MOVK #imm16 chunks
ARM64X = 0x7834                            # "4x"
GROUP = (b'mobile:mobile', b'000501:000501')
# entitlement file, byte for byte (ldid embeds the XML as written; keep it stable for reproducible builds)
ENTS_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
\t<key>platform-application</key><true/>
\t<key>com.apple.private.security.no-sandbox</key><true/>
\t<key>com.apple.private.security.no-container</key><true/>
\t<key>com.apple.private.security.container-required</key><false/>
\t<key>com.apple.private.skip-library-validation</key><true/>
\t<key>com.apple.private.security.storage-exempt.heritable</key><true/>
\t<key>com.apple.private.persona-mgmt</key><true/>
\t<key>com.apple.private.spawn-subsystem-root</key><true/>
</dict></plist>
'''
ENTS = plistlib.loads(ENTS_XML)


def die(m): sys.exit(f"  [patch_sileo] !! {m}")
def say(m): print(f"  [patch_sileo] {m}", flush=True)
def movz64(rd, imm, hw): return 0xD2800000 | (hw << 21) | (imm << 5) | rd
def movk64(rd, imm, hw): return 0xF2800000 | (hw << 21) | (imm << 5) | rd


def deb_data(path):
    """data.tar.* member of a .deb (ar archive)."""
    d = open(path, 'rb').read()
    if not d.startswith(b'!<arch>\n'): die(f"{path} is not a .deb")
    off = 8
    while off < len(d):
        name, size = d[off:off + 16].decode().strip().rstrip('/'), int(d[off + 48:off + 58])
        if name.startswith('data.tar'):
            blob = d[off + 60:off + 60 + size]
            return lzma.decompress(blob) if name.endswith('.xz') else blob
        off += 60 + size + (size & 1)
    die("no data.tar in the deb")


def text_range(d):
    if struct.unpack_from('<I', d, 0)[0] != 0xFEEDFACF: die("Sileo is not a thin 64-bit Mach-O")
    ncmds, off = struct.unpack_from('<I', d, 16)[0], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', d, off)
        if cmd == 0x19:
            for s in range(struct.unpack_from('<I', d, off + 64)[0]):
                so = off + 72 + s * 80
                if d[so:so + 16].rstrip(b'\0') == b'__text' and d[so + 16:so + 32].rstrip(b'\0') == b'__TEXT':
                    return struct.unpack_from('<I', d, so + 48)[0], struct.unpack_from('<Q', d, so + 40)[0]
        off += size
    die("__TEXT,__text not found")


def arm64e_sites(d):
    start, size = text_range(d)
    W = lambda o: struct.unpack_from('<I', d, o)[0]
    sites = []
    for o in range(start + 8, start + size, 4):
        w = W(o)
        if (w & 0xFFE00000) != 0xF2C00000 or (w >> 5) & 0xFFFF != ARM64E[2]: continue   # MOVK Xd, #0x6534, LSL #32
        rd = w & 0x1F
        if W(o - 4) == movk64(rd, ARM64E[1], 1) and W(o - 8) == movz64(rd, ARM64E[0], 0):
            sites.append((o, rd))
    if len(sites) != 2 or sites[1][0] - sites[0][0] > 0x100:
        die(f"expected the 2 'arm64e' literals of Jailbreak.init close together, found {[hex(o) for o, _ in sites]}")
    return sites


def patch_binary(path):
    d = bytearray(open(path, 'rb').read())
    if d.count(GROUP[0]) != 1: die("expected exactly one 'mobile:mobile' literal")
    d[:] = d.replace(*GROUP)
    sites = arm64e_sites(bytes(d))
    for o, rd in sites:
        struct.pack_into('<I', d, o, movk64(rd, ARM64X, 2))
    open(path, 'wb').write(d)
    say(f"chown group -> 000501:000501; arm64e literal -> arm64x at {', '.join(hex(o) for o, _ in sites)}")


def sign(app, ldid):
    ent = os.path.join(os.path.dirname(app), 'sileo.ent')
    open(ent, 'wb').write(ENTS_XML)
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)
    run(ldid, f'-I{BUNDLE_ID}', f'-S{ent}', '-Cadhoc', os.path.join(app, 'Sileo'))
    run(ldid, '-IgiveMeRoot', f'-S{ent}', os.path.join(app, 'giveMeRoot'))
    # codesign re-signs the main executable and reseals CodeResources (giveMeRoot is sealed as a resource)
    run('codesign', '--force', '--sign', '-', '--entitlements', ent, app)
    run('codesign', '-v', app)
    if plistlib.loads(subprocess.check_output([ldid, '-e', os.path.join(app, 'Sileo')])) != ENTS:
        die("entitlements changed while signing")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--deb', default=os.path.join(ROOT, 'payload/pkgs/sileo.deb'))
    ap.add_argument('--out', default=os.path.join(ROOT, 'payload/pkgs/Sileo.app.tar'))
    a = ap.parse_args()
    if hashlib.sha256(open(a.deb, 'rb').read()).hexdigest() != SILEO_SHA:
        die(f"{a.deb} is not the pinned Sileo 2.5.1 rootless deb (sha256 {SILEO_SHA})")
    ldid = shutil.which('ldid') or die("ldid not found (brew install ldid-procursus)")
    work = tempfile.mkdtemp(prefix='dualboot-sileo-')
    try:
        src = tarfile.open(fileobj=io.BytesIO(deb_data(a.deb)))
        members = [m for m in src.getmembers() if m.name == APP_PREFIX or m.name.startswith(APP_PREFIX + '/')]
        if not members: die("Sileo.app not found in the deb")
        app = os.path.join(work, 'Sileo.app')
        for m in members:
            rel = 'Sileo.app' + m.name[len(APP_PREFIX):]
            dst = os.path.join(work, rel)
            if m.isdir(): os.makedirs(dst, exist_ok=True)
            elif m.isfile():
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                open(dst, 'wb').write(src.extractfile(m).read()); os.chmod(dst, m.mode & 0o777)
            elif m.issym():
                os.makedirs(os.path.dirname(dst), exist_ok=True); os.symlink(m.linkname, dst)
        if not members[[m.name for m in members].index(APP_PREFIX + '/giveMeRoot')].mode & 0o4000:
            die("giveMeRoot is not setuid in the deb; refusing")
        patch_binary(os.path.join(app, 'Sileo'))
        sign(app, ldid)
        tmp = a.out + '.new'
        with tarfile.open(tmp, 'w', format=tarfile.PAX_FORMAT) as o:
            names = sorted({os.path.relpath(os.path.join(dp, n), work) for dp, dns, fns in os.walk(app) for n in dns + fns}
                           | {'Sileo.app'})
            for rel in names:
                p = os.path.join(work, rel)
                ti = o.gettarinfo(p, rel)
                ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, 'root', 'wheel'
                if rel == 'Sileo.app/giveMeRoot': ti.mode = 0o4755
                if ti.isfile():
                    with open(p, 'rb') as f: o.addfile(ti, f)
                else:
                    o.addfile(ti)
        os.replace(tmp, a.out)
        cd = subprocess.run(['codesign', '-dvvv', app], capture_output=True, text=True).stderr
        say(f"written {a.out} ({next((l for l in cd.splitlines() if l.startswith('CDHash=')), '?')})")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()
