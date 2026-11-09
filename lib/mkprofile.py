#!/usr/bin/env python3
"""Generate a dualboot version profile (profiles/<board>-<build>/) for any iOS 27.x build.

Every patch record is re-resolved in the binaries of THAT build - offsets are outputs, never copied from another
version. A profile made here starts as "tested": false.

  lib/patchfinder (semantic resolvers, `lib/patchfinder/resolve.py <component> <plan> <input> --json`):
    kernel-boot-jit.json             kernel boot-jit
    kernel-restore-nodebugger.json   kernel restore, minus kernel.debugger.*
    kernel-vm-fault-cs-bypass.json   kernel vm-fault-cs-bypass
    txm-boot-permissive.json         txm boot-permissive
    txm-cs-only.json                 txm boot-permissive, minus debug-mapping / secure-channel / permissive all-ones
    commcenter|coreauthd|ctkd|mobileactivationd.json   userland plans (need the root filesystem: --rootfs)
  dualboot resolvers (lib/kpatchfind.py):
    kernel-ramdisk.json, kernel-osb.json
  version independent: securityd/lockdownd/iconservicesagent.json = [] (OS B dylibs only),
                       lockdownd.ents-add.plist (profiles/_common)

usage: mkprofile.py --ipsw <X.ipsw | extracted dir> --board d421ap [--rootfs DIR] [--out DIR] [--force]
       mkprofile.py --userland <profile dir> --rootfs DIR      (fill the daemon records later)
"""
import argparse, hashlib, json, os, plistlib, shutil, subprocess, sys, tempfile, time, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import kpatchfind, pf

BOARD_PRODUCTS = {'d421ap': ['iPhone12,3'], 'd431ap': ['iPhone12,5'], 'n104ap': ['iPhone12,1'], 'd79ap': ['iPhone12,8'],
                  'j181ap': ['iPad12,1'], 'j182ap': ['iPad12,2']}
USERLAND = {  # userland plan (= profile file name) -> path in the root filesystem
    'coreauthd': 'System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd',
    'ctkd': 'System/Library/Frameworks/CryptoTokenKit.framework/ctkd',
    'mobileactivationd': 'usr/libexec/mobileactivationd',
    'commcenter': 'System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter',
}
EMPTY = ['securityd.json', 'lockdownd.json', 'iconservicesagent.json']
RESTORE_DROP = ('kernel.debugger.',)                       # kernel-restore-nodebugger
CS_ONLY_DROP = ('txm.debug-mapping.', 'txm.secure-channel.', 'txm.permissive-flags.all-ones')


def say(m): print(f"  [mkprofile] {m}", flush=True)
def die(m): sys.exit(f"  [mkprofile] !! {m}")


def resolve(component, plan, path):
    try:
        recs = pf.resolve(component, plan, path)
    except Exception as e:
        die(f"patchfinder {component} {plan} failed on {os.path.basename(path)}: {e}")
    if not recs: die(f"patchfinder {component} {plan}: no records")
    return recs


class Firmware:
    """An IPSW zip or a directory holding BuildManifest.plist + the component files at their manifest paths."""
    def __init__(self, src, board):
        self.src, self.board = src, board
        self.zip = zipfile.ZipFile(src) if os.path.isfile(src) else None
        self.tmp = tempfile.mkdtemp(prefix='dualboot-prof-')
        self.manifest = plistlib.loads(self.read('BuildManifest.plist'))
        ids = [i for i in self.manifest['BuildIdentities'] if i['Info'].get('DeviceClass', '').lower() == board
               and i['Info'].get('RestoreBehavior') == 'Erase']
        if not ids: die(f"{src}: no Erase identity for {board}")
        self.ident = ids[0]

    def read(self, rel):
        if self.zip: return self.zip.read(rel)
        p = os.path.join(self.src, rel)
        if not os.path.exists(p):
            hits = [os.path.join(d, rel) for d in os.listdir(self.src) if os.path.exists(os.path.join(self.src, d, rel))]
            if not hits: die(f"{rel} not found under {self.src}")
            p = os.path.join(self.src, hits[0])
        return open(p, 'rb').read()

    def comp(self, key):
        rel = self.ident['Manifest'][key]['Info']['Path']
        out = os.path.join(self.tmp, os.path.basename(rel))
        if not os.path.exists(out): open(out, 'wb').write(self.read(rel))
        return out

    @property
    def build(self): return self.manifest['ProductBuildVersion']
    @property
    def version(self): return self.manifest['ProductVersion']

    def close(self): shutil.rmtree(self.tmp, ignore_errors=True)


def write_json(path, recs):
    with open(path, 'w') as f:
        json.dump(recs, f, indent=1); f.write('\n')


def sha(path): return hashlib.sha256(open(path, 'rb').read()).hexdigest()


def gen_userland(pdir, rootfs):
    done = {}
    for name, rel in USERLAND.items():
        p = os.path.join(rootfs, rel)
        if not os.path.exists(p): die(f"rootfs is missing {rel}")
        recs = resolve('userland', name, p)
        write_json(os.path.join(pdir, f'{name}.json'), recs); done[name] = len(recs)
    say("userland: " + ", ".join(f"{k} {v}" for k, v in done.items()))
    finalize(pdir, pending_userland=False)


def finalize(pdir, **upd):
    pj = os.path.join(pdir, 'profile.json')
    prof = json.load(open(pj)) if os.path.exists(pj) else {}
    prof.update(upd)
    prof['files'] = {f: sha(os.path.join(pdir, f)) for f in sorted(os.listdir(pdir)) if f != 'profile.json'}
    json.dump(prof, open(pj, 'w'), indent=1)
    open(pj, 'a').write('\n')


def generate(src, board, out_root, rootfs=None, force=False):
    fw = Firmware(src, board)
    tmpdir = None
    try:
        pdir = os.path.join(out_root, f'{board}-{fw.build}')
        if os.path.exists(os.path.join(pdir, 'profile.json')) and not force:
            say(f"{pdir} already exists (use --force to regenerate)"); return pdir
        tmpdir = pdir + '.new'
        shutil.rmtree(tmpdir, ignore_errors=True); os.makedirs(tmpdir)
        say(f"iOS {fw.version} ({fw.build}) {board}: resolving every patch site for this build")
        K, T = fw.comp('KernelCache'), fw.comp('Ap,TrustedExecutionMonitor')
        counts = {}
        def put(name, recs):
            write_json(os.path.join(tmpdir, name), recs); counts[name] = len(recs)
        put('kernel-boot-jit.json', resolve('kernel', 'boot-jit', K))
        put('kernel-restore-nodebugger.json', [r for r in resolve('kernel', 'restore', K) if not r['id'].startswith(RESTORE_DROP)])
        put('kernel-vm-fault-cs-bypass.json', resolve('kernel', 'vm-fault-cs-bypass', K))
        bp = resolve('txm', 'boot-permissive', T)
        put('txm-boot-permissive.json', bp)
        put('txm-cs-only.json', [r for r in bp if not r['id'].startswith(CS_ONLY_DROP)])
        kc = kpatchfind.load_kernel(K)
        put('kernel-ramdisk.json', kpatchfind.ramdisk_set(kc))
        put('kernel-osb.json', kpatchfind.osb_set(kc))
        for n in EMPTY: put(n, [])
        shutil.copy2(os.path.join(ROOT, 'profiles/_common/lockdownd.ents-add.plist'), tmpdir)
        info = fw.ident['Info']
        prof = {
            'board': board, 'product_types': BOARD_PRODUCTS.get(board, fw.manifest.get('SupportedProductTypes', [])),
            'cpid': fw.ident.get('ApChipID', ''), 'bdid': fw.ident.get('ApBoardID', ''),
            'build': fw.build, 'version': fw.version,
            'ipsw_name': os.path.basename(src) if src.endswith('.ipsw') else '',
            'tested': False, 'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
            'generator': {'patchfinder': pf.version(),
                          'kpatchfind': kpatchfind.__doc__.splitlines()[0][:60]},
            'records': counts, 'pending_userland': True,
            'notes': 'generated by lib/mkprofile.py (lib/patchfinder + lib/kpatchfind); every site re-resolved for this build',
        }
        json.dump(prof, open(os.path.join(tmpdir, 'profile.json'), 'w'), indent=1)
        say("records: " + ", ".join(f"{k.replace('.json', '')} {v}" for k, v in counts.items() if v))
        if rootfs: gen_userland(tmpdir, rootfs)
        else: finalize(tmpdir)
        if os.path.exists(pdir):
            shutil.rmtree(pdir + '.prev', ignore_errors=True); os.rename(pdir, pdir + '.prev')
        os.rename(tmpdir, pdir)
        say(f"profile written: {pdir}" + ("" if rootfs else "  (daemon records pending: need the root filesystem)"))
        return pdir
    finally:
        fw.close()
        if tmpdir and os.path.isdir(tmpdir):      # a site failed to resolve: leave no half-written <board>-<build>.new
            shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ipsw'); ap.add_argument('--board', default='d421ap'); ap.add_argument('--rootfs')
    ap.add_argument('--out', default=os.path.join(ROOT, 'profiles')); ap.add_argument('--force', action='store_true')
    ap.add_argument('--userland', metavar='PROFILE_DIR', help='only (re)generate the daemon records of a profile')
    a = ap.parse_args()
    if a.userland:
        if not a.rootfs: die("--userland needs --rootfs")
        gen_userland(a.userland, a.rootfs); return
    if not a.ipsw: die("--ipsw is required")
    generate(a.ipsw, a.board.lower(), a.out, a.rootfs, a.force)


if __name__ == '__main__':
    main()
