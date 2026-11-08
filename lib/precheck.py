#!/usr/bin/env python3
"""Pre-check one iOS build for dualboot BEFORE the phone is touched (no DFU, no device needed).

Uses blacktop's `ipsw` to pull only what the patchers read - BuildManifest, kernelcache, TXM, iBSS, iBEC and
DeviceTree of the board (~70 MB, `ipsw extract --remote`, no 11 GB download) - then runs every patcher on them:

  1. profile   every kernel/TXM patch site re-resolved for this build (lib/patchfinder + lib/kpatchfind.py),
               unique and with its original bytes; an existing profile must match the fresh result exactly
  2. records   all record sets of both chains (setup: restore-nodebugger + vm-fault + TXM cs-only;
               2nd Data: boot-jit + ramdisk + osb + TXM boot-permissive) applied to the stock images: original
               bytes verified, no overlapping words
  3. iBoot     patch_iboot.py (image4 validation, boot-args slot) on iBSS and iBEC
  4. DT        dt_patch.py with the setup and the 2nd Data edit lists
  5. TSS       an APTicket for the setup chain: this build's own if Apple still signs it, otherwise the newest
               signed build's (the patched iBoot does not verify AP images)
  Daemon (userland) records need the root filesystem; they are resolved during install (prepare_rootfs).

The result is stored as "precheck" in profiles/<board>-<build>/profile.json. Exit status 0 = everything passed.
Relies on blacktop/ipsw (https://github.com/blacktop/ipsw) for the remote extraction.

usage: precheck.py --build 24B119 [--board d421ap] [--ipsw local.ipsw]
"""
import argparse, json, os, plistlib, re, shutil, subprocess, sys, tempfile, time, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import kpf, mkprofile, dt_patch

WORKROOT = os.environ.get('DUALBOOT_HOME') or os.path.expanduser('~/dualboot-work')
PROFILES = os.path.join(ROOT, 'profiles')
IPSW_MIN = (3, 1, 700)            # `ipsw extract --remote --pattern` as tested with this tool
COMPONENTS = ['KernelCache', 'Ap,TrustedExecutionMonitor', 'iBSS', 'iBEC', 'DeviceTree']
IBOOT_ARGS = {  # the longest literal each image gets in the tool (the boot-args slot must hold it)
    'iBSS': 'rd=md0 -v wdt=-1 serial=3 debug=0x2014e',
    'iBEC': 'jb=md0 -v serial=3 debug=0x2014e launchd_unsecure_cache=1 wdt=-1',
}
CHAINS = [  # (name, image key, record files, excluded id prefixes) - mirrors mk_kernel.py / mk_osb.py / mk_osbjb.py
    ('setup kernel', 'KernelCache', ['kernel-restore-nodebugger.json', 'kernel-vm-fault-cs-bypass.json'], ('kernel.identity',)),
    ('setup TXM', 'Ap,TrustedExecutionMonitor', ['txm-cs-only.json'], ()),
    ('2nd Data kernel', 'KernelCache', ['kernel-boot-jit.json', 'kernel-ramdisk.json', 'kernel-osb.json'], ('kernel.identity',)),
    ('2nd Data TXM', 'Ap,TrustedExecutionMonitor', ['txm-boot-permissive.json'], ()),
]
KERNEL_TXM_FILES = sorted({f for _, _, fs, _ in CHAINS for f in fs})

G, R, Y, N = '\033[1;32m', '\033[1;31m', '\033[1;33m', '\033[0m'
results = []


def ok(name, detail=''):
    results.append((name, True, detail)); print(f"   {G}✓{N} {name:10s} {detail}", flush=True)


def bad(name, detail):
    results.append((name, False, detail)); print(f"   {R}✗{N} {name:10s} {detail}", flush=True)


def info(name, detail):
    print(f"   {Y}•{N} {name:10s} {detail}", flush=True)


def ipsw_version():
    try:
        out = subprocess.run(['ipsw', 'version'], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return None
    m = re.search(r'Version:\s*(\d+)\.(\d+)\.(\d+)', out)
    return tuple(map(int, m.groups())) if m else None


def apple_builds(product):
    """ipsw.me: [{'version','build','url','signed'}] newest first, or [] when offline."""
    try:
        d = json.load(urllib.request.urlopen(f'https://api.ipsw.me/v4/device/{product}?type=ipsw', timeout=15))
    except Exception:
        return []
    return [{'version': f['version'], 'build': f['buildid'], 'url': f['url'], 'signed': bool(f['signed'])}
            for f in d.get('firmwares', [])]


def appledb_build(product, build):
    """Betas and RCs are not on ipsw.me: ask AppleDB through `ipsw download appledb --urls` (Apple CDN links)."""
    try:
        r = subprocess.run(['ipsw', 'download', 'appledb', '--os', 'iOS', '--device', product, '--build', build, '--urls'],
                           capture_output=True, text=True, timeout=180)
    except Exception:
        return None
    urls = [u for u in re.findall(r'https://\S+?_Restore\.ipsw', r.stdout + r.stderr) if product in u and f'_{build}_' in u]
    if not urls:
        return None
    m = re.search(r'_(\d+(?:\.\d+)+)_' + re.escape(build) + '_', urls[0])
    return {'version': m.group(1) if m else '?', 'build': build, 'url': urls[0], 'signed': False, 'source': 'appledb'}


def apple_build(product, build):
    """Release builds from ipsw.me, betas / RCs from AppleDB. 'signed' is only known for ipsw.me builds."""
    return next((b for b in apple_builds(product) if b['build'] == build), None) or appledb_build(product, build)


def latest_signed(product):
    """Newest build Apple still signs for product (its TSS ticket wraps the setup chain of any build)."""
    return next((b for b in apple_builds(product) if b['signed']), None)


def find_in(root, rel):
    for c in [os.path.join(root, rel)] + [os.path.join(root, d, rel) for d in (os.listdir(root) if os.path.isdir(root) else [])]:
        if os.path.isfile(c): return c
    return None


def remote_extract(url, pattern, out):
    r = subprocess.run(['ipsw', 'extract', '--remote', url, '--pattern', pattern, '-o', out],
                       capture_output=True, text=True)
    if r.returncode: raise SystemExit(f"ipsw extract --remote failed:\n{(r.stdout + r.stderr)[-800:]}")


def has_identity(man, board):
    m = plistlib.load(open(man, 'rb'))
    return any(i['Info'].get('DeviceClass', '').lower() == board for i in m['BuildIdentities'])


def fetch_parts(url, build, board, components=COMPONENTS):
    """BuildManifest + the board's `components` of `build`, cached in $DUALBOOT_HOME/ipsw-parts/<IPSW name>.
    One directory per IPSW: iPhone 11 (iPhone12,1) and 11 Pro / Pro Max (iPhone12,3 + 12,5) ship separate IPSWs of
    the same build. Returns the directory holding BuildManifest.plist (component paths are relative to it)."""
    name = os.path.basename(urllib.parse.urlparse(url).path).replace('_Restore.ipsw', '').replace('.ipsw', '') or build
    root = os.path.join(WORKROOT, 'ipsw-parts', name)
    legacy = os.path.join(WORKROOT, 'ipsw-parts', build)            # older cache layout: one directory per build
    if not os.path.exists(root) and os.path.isdir(legacy):
        lm = find_in(legacy, 'BuildManifest.plist')
        if lm and has_identity(lm, board):
            os.rename(legacy, root)
    os.makedirs(root, exist_ok=True)
    if not find_in(root, 'BuildManifest.plist'):
        remote_extract(url, r'^BuildManifest\.plist$', root)
    man = find_in(root, 'BuildManifest.plist') or sys.exit("BuildManifest.plist not downloaded")
    m = plistlib.load(open(man, 'rb'))
    ids = [i for i in m['BuildIdentities'] if i['Info'].get('DeviceClass', '').lower() == board
           and i['Info'].get('RestoreBehavior') == 'Erase']
    if not ids: sys.exit(f"{build}: no Erase identity for {board}")
    paths = [ids[0]['Manifest'][k]['Info']['Path'] for k in components]
    missing = [p for p in paths if not find_in(root, p)]
    if missing:
        remote_extract(url, '^(' + '|'.join(re.escape(p) for p in missing) + ')$', root)
    still = [p for p in paths if not find_in(root, p)]
    if still: sys.exit(f"not downloaded: {still}")
    return os.path.dirname(man)


def raw_of(path):
    from pyimg4 import IM4P
    d = open(path, 'rb').read()
    if d[:4] == b'\xcf\xfa\xed\xfe': return d
    p = IM4P(d)
    try: p.payload.decompress()
    except Exception: pass
    return bytes(p.payload.output().data)


def record_keys(path):
    txt = open(path).read().strip()
    return sorted((r['id'], r['offset'], r['originalBytes'], r['replacementBytes']) for r in (json.loads(txt) if txt else []))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', required=True); ap.add_argument('--board', default='d421ap')
    ap.add_argument('--ipsw', help='local IPSW or an IPSW URL (otherwise found on ipsw.me / AppleDB; only the needed parts '
                                   'are fetched with ipsw --remote)')
    a = ap.parse_args()
    board = a.board.lower()
    product = mkprofile.BOARD_PRODUCTS.get(board, [''])[0]
    print(f"== pre-check {board} ({product}) build {a.build}", flush=True)

    v = ipsw_version()
    if not v: sys.exit(f"{R}ipsw (blacktop) not installed - run ./setup.sh{N}")
    if v < IPSW_MIN: sys.exit(f"{R}ipsw {'.'.join(map(str, v))} is too old (need >= {'.'.join(map(str, IPSW_MIN))}): "
                              f"brew upgrade blacktop/tap/ipsw{N}")
    apple = apple_build(product, a.build)
    tmp = tempfile.mkdtemp(prefix='dualboot-precheck-')
    try:
        # ---------------------------------------------------------------- 0. sources
        if a.ipsw and not a.ipsw.startswith(('http://', 'https://')):
            src = a.ipsw
            info('source', f"local IPSW {a.ipsw}")
        else:
            url = a.ipsw or (apple or {}).get('url')
            if not url: sys.exit(f"{R}{a.build}: not found on ipsw.me or AppleDB for {product} (or offline) - pass --ipsw <file or URL>{N}")
            print(f"   fetching boot components with ipsw --remote (iOS {(apple or {}).get('version', a.build)}"
                  f"{', AppleDB' if (apple or {}).get('source') == 'appledb' else ''}) ...", flush=True)
            src = fetch_parts(url, a.build, board)
            info('source', f"{src}")
        fw = mkprofile.Firmware(src, board)
        if fw.build != a.build: sys.exit(f"{R}firmware is {fw.build}, expected {a.build}{N}")
        comp = {k: fw.comp(k) for k in COMPONENTS}

        # ---------------------------------------------------------------- 1. profile
        pdir = os.path.join(PROFILES, f'{board}-{a.build}')
        existed = os.path.exists(os.path.join(pdir, 'profile.json'))
        try:
            gen = mkprofile.generate(src, board, tmp if existed else PROFILES, rootfs=None, force=True)
            if existed:
                diff = [f for f in KERNEL_TXM_FILES if record_keys(os.path.join(gen, f)) != record_keys(os.path.join(pdir, f))]
                if diff: bad('profile', f"existing profile differs from a fresh resolve: {diff}")
                else: ok('profile', f"{pdir.replace(ROOT + '/', '')}: matches a fresh resolve of every site")
            else:
                ok('profile', f"generated {pdir.replace(ROOT + '/', '')} (every site unique, original bytes recorded)")
        except SystemExit as e:
            bad('profile', f"a patch site could not be resolved uniquely: {e}")
            raise SystemExit(1)

        # ---------------------------------------------------------------- 2. records on the stock images
        for name, key, files, excl in CHAINS:
            try:
                img = raw_of(comp[key])
                recs = kpf.load_records([os.path.join(pdir, f) for f in files], exclude_prefixes=excl)
                words = kpf.records_to_words(img, recs)
                offs = [o for o, _, _ in words]
                if len(offs) != len(set(offs)): bad('records', f"{name}: overlapping words")
                else: ok('records', f"{name}: {len(recs)} records / {len(words)} words apply cleanly")
            except SystemExit as e:
                bad('records', f"{name}: {e}")

        # ---------------------------------------------------------------- 3. iBoot
        for key, args in IBOOT_ARGS.items():
            rin, rout = os.path.join(tmp, key + '.raw'), os.path.join(tmp, key + '.patched')
            open(rin, 'wb').write(raw_of(comp[key]))
            r = subprocess.run([sys.executable, os.path.join(HERE, 'patch_iboot.py'), '--no-fsboot',
                                f'--boot-args={args}', rin, rout], capture_output=True, text=True)
            if r.returncode: bad('iBoot', f"{key}: {(r.stdout + r.stderr).strip().splitlines()[-1]}")
            else: ok('iBoot', f"{key}: " + "; ".join(l.split('@')[0].strip() for l in r.stdout.strip().splitlines()))

        # ---------------------------------------------------------------- 4. DeviceTree
        dt = os.path.join(tmp, 'dt.raw'); open(dt, 'wb').write(raw_of(comp['DeviceTree']))
        for name, ops in (('setup', dt_patch.SETUP_OPS), ('2nd Data', dt_patch.OSB_OPS)):
            r = subprocess.run([sys.executable, os.path.join(HERE, 'dt_patch.py'), dt, dt + '.' + name.replace(' ', '')] + ops,
                               capture_output=True, text=True)
            if r.returncode: bad('DT', f"{name}: {(r.stdout + r.stderr).strip().splitlines()[-1]}")
            else: ok('DT', f"{name}: {len(ops) // 2} edits")

        # ---------------------------------------------------------------- 5. TSS / userland
        # The patched iBoot does not verify AP images, so an unsigned build borrows the TSS ticket (and SEP
        # image) of the newest signed build for the setup chain; OS B itself uses the ticket installed on the phone.
        if apple is not None and apple['signed']:
            ok('TSS', f"Apple signs iOS {apple['version']} ({a.build}): its own APTicket is used for the setup chain")
        else:
            ls = latest_signed(product)
            if ls: ok('TSS', f"{a.build} is not signed: the setup chain will use the APTicket of iOS {ls['version']} ({ls['build']})")
            elif apple is None: info('TSS', "signing status unknown (offline)")
            else: bad('TSS', f"Apple signs no build for {product} right now: no APTicket for the setup chain")
        prof = json.load(open(os.path.join(pdir, 'profile.json')))
        if prof.get('pending_userland'):
            info('daemons', "commcenter/coreauthd/ctkd/mobileactivationd are resolved during install (needs the rootfs)")

        # ---------------------------------------------------------------- result
        passed = all(r[1] for r in results)
        prof['precheck'] = {'ok': passed, 'date': time.strftime('%Y-%m-%d %H:%M:%S'),
                            'ipsw': '.'.join(map(str, v)), 'signed': apple['signed'] if apple else None,
                            'failed': [f"{n}: {d}" for n, s, d in results if not s]}
        json.dump(prof, open(os.path.join(pdir, 'profile.json'), 'w'), indent=1)
        open(os.path.join(pdir, 'profile.json'), 'a').write('\n')
        print(f"== {G + 'PASS' if passed else R + 'FAIL'}{N}: {sum(r[1] for r in results)}/{len(results)} checks", flush=True)
        sys.exit(0 if passed else 1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
