#!/usr/bin/env python3
"""dualboot - tethered dual-boot ("2nd Data") for A13 (T8030) devices: iPhone 11 / 11 Pro / 11 Pro Max,
iPhone SE (2nd gen), iPad (9th gen).

2nd Data = the phone's own stock, sealed System volume + a separate APFS volume "DataB" as /private/var, booted
from pwned DFU with a patched kernel/iBoot and a rootless jailbreak (Procursus, Sileo, ElleKit, all fixes).
Nothing on the stock OS is modified: a normal reboot always returns to stock iOS.

  ./boot.sh                      boot 2nd Data (phone in pwned DFU). Use this every time.
  ./dualboot.py                  same as boot if 2nd Data is installed for this phone, otherwise install
  ./dualboot.py install          first-time setup (only when no DataB exists yet, or to repair)
  ./dualboot.py remove           delete DataB and our Preboot files (back to a single stock OS)
  ./dualboot.py provision        (re)apply all userland fixes over SSH while 2nd Data is running
  ./dualboot.py status | doctor  show workspace / check the Mac
  ./dualboot.py versions | select | precheck | profile
                                 pick the iOS build installed on the phone; profiles are generated per build
"""
import argparse, glob, json, os, shutil, subprocess, sys, time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, 'lib'))
from common import (serial_source, parse_ticket, SerialFileTail,
                    say, warn, die, run, ask, host_check, irec_query, wait_dfu, board_of, list_profiles,
                    find_profile, Workspace, SSH, device_udid, WORKROOT, LIB, PAYLOAD, BOARD_PRODUCTS, BOARD_HELP)

# ------------------------------------------------------------------------------------------- workspaces
def workspaces_for(ecid):
    e = ecid.lower().replace('0x', '').zfill(16)
    out = []
    for d in sorted(glob.glob(os.path.join(WORKROOT, e + '-*'))):
        st = os.path.join(d, 'state.json')
        s = json.load(open(st)) if os.path.exists(st) else {}
        out.append((d, s))
    return out

def installed_ws(q):
    """Workspace of this phone that has a bootable 2nd Data build, or None."""
    board = board_of(q)
    for d, s in reversed(workspaces_for(q['ECID'])):
        if s.get('installed') and os.path.exists(os.path.join(d, 'build/osbjb/Kernelcache.img4')):
            prof = find_profile(s.get('board', board), s['build'])
            if prof:
                return Workspace(q['ECID'], prof)
    return None

def current_device(allow_ibec=True):
    """irecovery view of the phone: pwned DFU, or (allow_ibec) our iBEC already running from an earlier try."""
    q = irec_query()
    if q and q.get('MODE') == 'DFU' and 'usbliter8' in q.get('PWND', ''):
        return q, False
    if allow_ibec and q and q.get('MODE') == 'Recovery' and 'NONC' in q and 'PWND' not in q:
        return q, True
    return wait_dfu(pwned=True), False

# ------------------------------------------------------------------------------------------- boot
def cmd_boot(a):
    q, resume = current_device()
    ws = installed_ws(q)
    if not ws:
        die("2nd Data is not installed for this iPhone (no workspace in ~/dualboot-work).\n"
            "    -> run: ./dualboot.py install")
    say(f"iPhone ECID {q['ECID']}  board {ws.profile['board']}  iOS {ws.profile['version']} ({ws.profile['build']})")
    say("Boot 2nd Data ..." + (" (iBEC already running - continuing from the firmware stage)" if resume else ""))
    args = ['--osbjb'] + (['--resume'] if resume else [])
    r = run(sys.executable, os.path.join(LIB, 'boot_chain.py'), *args, env=ws.env(), check=False)
    if r.returncode:
        die("sending the boot chain failed - put the phone back into pwned DFU and run ./boot.sh again")
    ws.state['last_boot'] = time.strftime('%Y-%m-%d %H:%M:%S'); ws.save()
    if a.no_wait:
        say("Chain sent. 2nd Data is booting."); return
    say("Waiting for 2nd Data (SSH) ...")
    udid = None
    for _ in range(90):
        udid = device_udid(q['ECID'])
        if udid: break
        time.sleep(2)
    ssh = SSH(ws, udid) if udid else None
    if ssh and ssh.wait(timeout=300):
        say("2nd Data is up. Jailbreak ready (SSH: ./dualboot.py ssh).")
        say("A normal reboot returns to stock iOS. To boot 2nd Data again: pwned DFU -> ./boot.sh")
    else:
        warn("no SSH after 5 minutes - check the screen (verbose boot) or the UART log")

# ------------------------------------------------------------------------------------------- status / doctor
def cmd_status(a):
    say(f"workspace root: {WORKROOT}")
    for p in list_profiles():
        say(f"profile {p['name']}: {', '.join(p['product_types'])} iOS {p['version']} ({p['build']})"
            f"{'' if p.get('tested') else '  [not device-tested]'}")
    for d in sorted(glob.glob(os.path.join(WORKROOT, '*'))):
        st = os.path.join(d, 'state.json')
        if not os.path.exists(st):
            continue
        s = json.load(open(st))
        say(f"  {os.path.basename(d)}: installed={s.get('installed', False)} last_boot={s.get('last_boot', '-')}")
    q = irec_query()
    if q:
        say(f"device: MODE={q.get('MODE')} CPID={q.get('CPID')} BDID={q.get('BDID')} ECID={q.get('ECID')} "
            f"PWND={q.get('PWND', '-')}")

def cmd_doctor(a):
    bad = host_check()
    if bad:
        warn("missing:"); [print("     -", b) for b in bad]; sys.exit(1)
    say("Mac OK: all tools present (irecovery, iproxy, ldid, ipsw, pyimg4, pyusb, usbliter8ctl)")

def cmd_ssh(a):
    q = irec_query()
    ecid = a.ecid or (q or {}).get('ECID')
    cands = [Workspace(d.split('/')[-1].split('-')[0], find_profile(s.get('board'), s.get('build')))
             for d, s in (workspaces_for(ecid) if ecid else []) if s.get('installed')]
    if not cands:
        # phone is booted (not in irecovery): take the only installed workspace
        alls = [(d, json.load(open(os.path.join(d, 'state.json')))) for d in glob.glob(os.path.join(WORKROOT, '*'))
                if os.path.exists(os.path.join(d, 'state.json'))]
        alls = [(d, s) for d, s in alls if s.get('installed')]
        if len(alls) != 1: die("cannot tell which phone - use --ecid")
        d, s = alls[0]; cands = [Workspace(os.path.basename(d).split('-')[0], find_profile(s['board'], s['build']))]
    ws = cands[-1]
    udid = device_udid(ws.ecid) or die("no iPhone on USB (is 2nd Data booted?)")
    ssh = SSH(ws, udid); ssh._iproxy()
    os.execvp('ssh', ['ssh', *ssh._base(), '-p', '2222', 'root@localhost', *a.remote])

def build_osb(ws):
    ws.py('mk_osb.py', capture=True)
    r = ws.py('mk_osbjb.py', capture=True)
    for l in r.stdout.strip().splitlines()[-4:]:
        print('    ' + l)

def only_installed_ws(ecid=None):
    alls = []
    for d in sorted(glob.glob(os.path.join(WORKROOT, '*'))):
        st = os.path.join(d, 'state.json')
        if os.path.exists(st):
            s = json.load(open(st))
            if s.get('installed') and (not ecid or os.path.basename(d).startswith(ecid.lower().replace('0x', '').zfill(16))):
                alls.append((d, s))
    if len(alls) != 1:
        die("need exactly one installed workspace (use --ecid)")
    d, s = alls[0]
    return Workspace(os.path.basename(d).split('-')[0], find_profile(s['board'], s['build']))

def cmd_rebuild(a):
    ws = only_installed_ws(a.ecid)
    say(f"rebuilding the 2nd Data artifacts in {ws.root}")
    build_osb(ws)

# ------------------------------------------------------------------------------------------- auto
def cmd_auto(a):
    q, resume = current_device()
    if installed_ws(q):
        return cmd_boot(a)
    say("No 2nd Data for this iPhone yet -> install")
    return cmd_install(a)

# ------------------------------------------------------------------------------------------- prepare (host side)
IPSW_KEYS = ['BuildManifest.plist']   # + every BuildManifest component the chains use (see osbcfg)

# ------------------------------------------------------------------------------------------- iOS versions
# OS B runs on the phone's own stock System volume (same cryptexes, same static trust cache), so it must be the
# build that is installed on the phone. Any iOS 27.x build can be selected: its profile (every patch site) is
# generated from that build's IPSW by lib/mkprofile.py (lib/patchfinder + lib/kpatchfind.py), never copied.
SELECTED = os.path.join(WORKROOT, 'selected-version.json')

def load_selected():
    try:
        return json.load(open(SELECTED))
    except Exception:
        return {}

def save_selected(**kw):
    os.makedirs(WORKROOT, exist_ok=True)
    json.dump(kw, open(SELECTED, 'w'), indent=1)

def public_builds(product):
    """iOS 27.x IPSWs Apple published for this product (ipsw.me), newest first."""
    import urllib.request
    try:
        d = json.load(urllib.request.urlopen(f'https://api.ipsw.me/v4/device/{product}?type=ipsw', timeout=15))
    except Exception as e:
        warn(f"could not get the IPSW list from ipsw.me ({e})")
        return []
    return [dict(version=f['version'], build=f['buildid'], signed=bool(f['signed']), url=f['url'])
            for f in d.get('firmwares', []) if f['version'].split('.')[0] == '27']

def detect_installed():
    """(product type, version, build) of a phone booted into iOS and connected over USB, else None."""
    vals = []
    for k in ('ProductType', 'ProductVersion', 'BuildVersion'):
        r = run('ideviceinfo', '-k', k, check=False, capture=True)
        vals.append(r.stdout.strip() if r.returncode == 0 else '')
    return tuple(vals) if all(vals) else None

def detect_board():
    """Board of the iPhone on USB: from DFU/recovery (CPID/BDID) or from iOS (ProductType); None if unknown."""
    q = irec_query()
    if q and q.get('CPID'):
        return board_of(q)
    det = detect_installed()
    return {v: k for k, v in BOARD_PRODUCTS.items()}.get(det[0]) if det else None

def pick_board(a=None):
    """--board, else the connected iPhone, else the last selection, else iPhone 11 Pro."""
    return (getattr(a, 'board', None) or detect_board() or load_selected().get('board') or 'd421ap').lower()

def version_choices(board):
    """[(build, version, label)] - local profiles + Apple's iOS 27.x builds for the board."""
    local = {p['build']: p for p in list_profiles() if p['board'] == board}
    pub = {b['build']: b for b in public_builds(BOARD_PRODUCTS.get(board, 'iPhone12,3'))}
    out = []
    for build in sorted(set(local) | set(pub), key=lambda b: (pub.get(b, local.get(b, {})).get('version', ''), b), reverse=True):
        p, b = local.get(build), pub.get(build)
        ver = (b or p)['version']
        tags = []
        if p:
            tags.append('tested on device' if p.get('tested') else 'generated profile, not device-tested')
            pc = p.get('precheck')
            if pc: tags.append('pre-check passed' if pc.get('ok') else 'pre-check FAILED')
        else:
            tags.append('no profile yet (pre-check generates it)')
        if b: tags.append('signed by Apple' if b['signed'] else 'no longer signed')
        out.append((build, ver, f"iOS {ver} ({build}) - " + ", ".join(tags)))
    return out

def ensure_profile(board, build, version='', ipsw=None):
    """Profile for board/build; generated from the IPSW when this build has none yet."""
    prof = find_profile(board, build)
    if prof:
        return prof
    pseudo = {'board': board, 'build': build, 'version': version, 'product_types': [BOARD_PRODUCTS.get(board, '')]}
    ipsw = find_ipsw(pseudo, ipsw)
    say(f"no profile for iOS {version} ({build}) yet: resolving every patch site in its IPSW ...")
    run(sys.executable, os.path.join(LIB, 'mkprofile.py'), '--ipsw', ipsw, '--board', board)
    return find_profile(board, build) or die(f"could not generate a profile for {build}")

def complete_profile(ws):
    """Daemon (userland) records need the root filesystem; fill them in once prepare_rootfs has run."""
    if ws.profile.get('pending_userland'):
        say("profile: resolving the daemon patches (commcenter, coreauthd, ctkd, mobileactivationd) ...")
        run(sys.executable, os.path.join(LIB, 'mkprofile.py'), '--userland', ws.profile['dir'],
            '--rootfs', ws.p('rootfs'))
        ws.profile = find_profile(ws.profile['board'], ws.profile['build'])

def cmd_versions(a):
    board = pick_board(a)
    ch = version_choices(board)
    if getattr(a, 'plain', False):
        for build, ver, label in ch:
            print(f"{build}|{ver}|{label}")
        return
    sel = load_selected()
    det = detect_installed()
    say(f"Board {board}. Selected: {('iOS ' + sel['version'] + ' (' + sel['build'] + ')') if sel.get('build') else 'none'}")
    if det:
        say(f"iPhone running iOS (USB): {det[0]} iOS {det[1]} ({det[2]})")
    for build, ver, label in ch:
        print(f"   {'*' if sel.get('build') == build else ' '} {label}")

def cmd_select(a):
    board = pick_board(a)
    if a.auto:
        det = detect_installed() or die("no iPhone running iOS on USB (unlock it and tap Trust)")
        board = {v: k for k, v in BOARD_PRODUCTS.items()}.get(det[0]) or die(f"{det[0]} is not supported")
        build, ver = det[2], det[1]
    elif a.ipsw:
        import zipfile, plistlib
        m = plistlib.loads(zipfile.ZipFile(a.ipsw).read('BuildManifest.plist'))
        build, ver = m['ProductBuildVersion'], m['ProductVersion']
    elif a.build:
        build = a.build
        ver = next((v for b, v, _ in version_choices(board) if b == build), '')
        if not ver:     # a beta / RC (not on ipsw.me): AppleDB
            import precheck
            ver = (precheck.apple_build(BOARD_PRODUCTS.get(board, ''), build) or {}).get('version', '')
    else:
        ch = version_choices(board)
        for i, (_, _, label) in enumerate(ch):
            print(f"   {i + 1}. {label}")
        n = input("   number: ").strip()
        build, ver = ch[int(n) - 1][:2]
    if not ver.startswith('27'):
        warn(f"iOS {ver or '?'}: this tool targets iOS 27.x (T8030)")
    save_selected(board=board, build=build, version=ver, ipsw=os.path.abspath(a.ipsw) if a.ipsw else '')
    say(f"selected iOS {ver} ({build}) for {board}. It MUST be the iOS version installed on the phone.")
    if not a.no_precheck and not run_precheck(board, build, a.ipsw):
        warn("pre-check failed - see above; install will refuse this build until it passes")

def run_precheck(board, build, ipsw=None):
    """lib/precheck.py: every patcher on this build's boot components (fetched with ipsw --remote), no device."""
    r = run(sys.executable, os.path.join(LIB, 'precheck.py'), '--build', build, '--board', board,
            *(['--ipsw', ipsw] if ipsw else []), check=False)
    return r.returncode == 0

def cmd_precheck(a):
    sel = load_selected()
    build = a.build or sel.get('build') or die("no iOS version selected (dualboot.py select)")
    board = a.board or sel.get('board') or pick_board(a)
    sys.exit(0 if run_precheck(board, build, a.ipsw or (sel.get('ipsw') or None if sel.get('build') == build else None)) else 1)

def cmd_profile(a):
    run(sys.executable, os.path.join(LIB, 'mkprofile.py'), '--ipsw', a.ipsw, '--board', pick_board(a),
        *(['--force'] if a.force else []), *(['--rootfs', a.rootfs] if a.rootfs else []))

def ipsw_products(path):
    """SupportedProductTypes of an IPSW's BuildManifest (iPad IPSWs are named by marketing name, not iPad12,1)."""
    import zipfile, plistlib
    try:
        with zipfile.ZipFile(path) as z:
            return plistlib.loads(z.read('BuildManifest.plist')).get('SupportedProductTypes', [])
    except Exception:
        return []

def find_ipsw(prof, given=None):
    if given:
        return given if os.path.exists(given) else die(f"IPSW not found: {given}")
    names = [prof.get('ipsw_name', '')]
    for d in (os.path.expanduser('~/Downloads'), os.path.expanduser('~/Desktop'), os.path.join(WORKROOT, 'ipsw')):
        for n in names:
            if n and os.path.exists(os.path.join(d, n)):
                return os.path.join(d, n)
        for f in glob.glob(os.path.join(d, f"*_{prof['build']}_Restore.ipsw")):
            if any(pt in f for pt in prof['product_types']) or set(prof['product_types']) & set(ipsw_products(f)):
                return f
    dst = os.path.join(WORKROOT, 'ipsw'); os.makedirs(dst, exist_ok=True)
    say(f"downloading the IPSW {prof['product_types'][0]} {prof['build']} (~11 GB) into {dst} ...")
    run('ipsw', 'download', 'ipsw', '--device', prof['product_types'][0], '--build', prof['build'], '--output', dst, check=False)
    got = glob.glob(os.path.join(dst, f"*{prof['build']}*.ipsw"))
    if not got:     # betas / RCs are not on ipsw.me: AppleDB has their Apple CDN links
        run('ipsw', 'download', 'appledb', '--os', 'iPadOS' if prof['product_types'][0].startswith('iPad') else 'iOS',
            '--device', prof['product_types'][0], '--build', prof['build'],
            '--output', dst, '--confirm', check=False)
        got = glob.glob(os.path.join(dst, '**', f"*{prof['build']}*.ipsw"), recursive=True)
    return got[0] if got else die("IPSW download failed")

def extract_ipsw(ws, ipsw):
    import zipfile, plistlib
    out = ws.p('build/ipsw'); os.makedirs(out, exist_ok=True)
    z = zipfile.ZipFile(ipsw)
    z.extract('BuildManifest.plist', out)
    m = plistlib.load(open(os.path.join(out, 'BuildManifest.plist'), 'rb'))
    if m.get('ProductBuildVersion') != ws.profile['build']:
        die(f"the IPSW is {m.get('ProductBuildVersion')}, the profile needs {ws.profile['build']}")
    keys = ['ANE', 'AOP', 'AVE', 'Ap,SecurePageTableMonitor', 'Ap,TrustedExecutionMonitor', 'GFX', 'ISP', 'PMP',
            'StaticTrustCache', 'SIO', 'WCHFirmwareUpdater', 'KernelCache', 'DeviceTree', 'iBEC', 'iBSS',
            'RestoreRamDisk', 'RestoreTrustCache', 'RestoreSEP']
    ident = [b for b in m['BuildIdentities'] if b['Info'].get('DeviceClass', '').lower() == ws.profile['board']
             and b['Info'].get('RestoreBehavior') == 'Erase'][0]
    keys = [k for k in keys if k in ident['Manifest']]     # iPads have no WCHFirmwareUpdater (wireless charging)
    for k in keys:
        path = ident['Manifest'][k]['Info']['Path']
        if not os.path.exists(os.path.join(out, path)):
            z.extract(path, out)
    say(f"IPSW: extracted {len(keys)} components")

def prepare_rootfs(ws, ipsw):
    """Stock binaries the patched daemons are built from, the launchd job cache (System/Library/xpc) and the system
    apps (private/var/staged_system_apps: the restore moves them off the System volume, so rdsetup cannot copy them
    from the phone; install_system_apps uploads them to DataB)."""
    need = [p.lstrip('/') for _, p, _ in DAEMONS] + ['System/Library/xpc', 'private/var/staged_system_apps']
    if all(os.path.exists(ws.p('rootfs', n)) for n in need):
        return
    tmp = ws.p('build/fsdmg'); shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)
    say("rootfs: extracting + decrypting the filesystem DMG (needs network for the AEA key; a few minutes, ~10 GB temporary) ...")
    r = run('ipsw', 'extract', '--dmg', 'fs', '-o', tmp, ipsw, capture=True)
    log = r.stdout + r.stderr
    dmgs = glob.glob(os.path.join(tmp, '**', '*.dmg'), recursive=True)
    # iOS 18+ IPSWs carry the filesystem as an AEA archive and `ipsw extract --dmg` leaves it encrypted (.dmg.aea):
    # `ipsw fw aea` fetches its key from Apple (fcs-key URL in the archive header) and writes the plain .dmg
    for aea in [] if dmgs else glob.glob(os.path.join(tmp, '**', '*.dmg.aea'), recursive=True):
        say(f"rootfs: decrypting {os.path.basename(aea)} ...")
        r = run('ipsw', 'fw', 'aea', '-o', tmp, aea, check=False, capture=True)
        log += r.stdout + r.stderr
        os.remove(aea)
        dmgs = glob.glob(os.path.join(tmp, '**', '*.dmg'), recursive=True)
    if not dmgs:
        die("could not extract the filesystem DMG (ipsw output below; the AEA key needs network access)\n" + log[-1500:])
    mnt = ws.p('build/fsmnt'); os.makedirs(mnt, exist_ok=True)
    run('hdiutil', 'attach', '-readonly', '-nobrowse', '-noverify', '-mountpoint', mnt, dmgs[0], capture=True)
    try:
        for n in need:
            src, dst = os.path.join(mnt, n), ws.p('rootfs', n)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.lexists(src):
                warn(f"rootfs: the filesystem DMG has no /{n}")
            elif os.path.isdir(src):
                shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
    finally:
        run('hdiutil', 'detach', mnt, check=False, capture=True)
        shutil.rmtree(tmp, ignore_errors=True)
    say("rootfs: done")

def prepare_tickets(ws):
    """TSS-personalised IM4M (for the setup chain and the SEP image) + rsep.img4. Needs the phone in (pwned) DFU."""
    if os.path.exists(ws.p('out/apticket.im4m')) and os.path.exists(ws.p('out/rsep.img4')):
        return
    manifest = ws.p('build/ipsw/BuildManifest.plist')
    sep = glob.glob(ws.p('build/ipsw/Firmware/all_flash/sep-firmware.*.RELEASE.im4p'))
    import precheck
    product = ws.profile['product_types'][0]
    me = precheck.apple_build(product, ws.profile['build'])
    if me is not None and not me['signed']:
        # The patched iBoot does not verify AP images: borrow the newest signed build's ticket (and its SEP image,
        # so ticket and SEP digest match) for the setup chain. OS B later uses the ticket installed on the phone.
        latest = precheck.latest_signed(product) or die(f"Apple signs no iOS build for {product} right now")
        say(f"iOS {ws.profile['version']} is no longer signed: using the APTicket of iOS {latest['version']} "
            f"({latest['build']}) for the setup chain")
        d = precheck.fetch_parts(latest['url'], latest['build'], ws.profile['board'], ['RestoreSEP'])
        manifest = os.path.join(d, 'BuildManifest.plist')
        sep = glob.glob(os.path.join(d, 'Firmware/all_flash/sep-firmware.*.RELEASE.im4p'))
    say("TSS: requesting an APTicket for this phone from Apple ...")
    r = run(sys.executable, os.path.join(LIB, 'get_apticket.py'), manifest,
            ws.p('out/apticket.im4m'), '--board', ws.profile['board'], check=False, capture=True)
    if r.returncode or not os.path.exists(ws.p('out/apticket.im4m')):
        die("TSS request failed\n" + (r.stdout + r.stderr)[-800:])
    if not sep:
        die("sep-firmware not found")
    run(sys.executable, os.path.join(LIB, 'mkimg4.py'), sep[0], ws.p('out/apticket.im4m'), ws.p('out/rsep.img4'),
        '--tag', 'rsep', capture=True)

def prepare_iboot(ws):
    from pyimg4 import IM4P
    import plistlib
    m = plistlib.load(open(ws.p('build/ipsw/BuildManifest.plist'), 'rb'))
    ident = [b for b in m['BuildIdentities'] if b['Info'].get('DeviceClass', '').lower() == ws.profile['board']
             and b['Info'].get('RestoreBehavior') == 'Erase'][0]
    for key, out, args in (('iBSS', 'iBoot.min.raw', 'rd=md0 -v wdt=-1 serial=3 debug=0x2014e'),
                           ('iBEC', 'iBoot.osb.raw', '-v serial=3 debug=0x2014e launchd_unsecure_cache=1 wdt=-1')):
        if os.path.exists(ws.p('out', out)):
            continue
        p = IM4P(open(ws.p('build/ipsw', ident['Manifest'][key]['Info']['Path']), 'rb').read())
        try:
            p.payload.decompress()
        except Exception:
            pass
        raw = ws.p('build', key + '.stock.raw'); open(raw, 'wb').write(p.payload.output().data)
        run(sys.executable, os.path.join(LIB, 'patch_iboot.py'), '--no-fsboot', f'--boot-args={args}', raw,
            ws.p('out', out), capture=True)

def build_setup_chain(ws, mode):
    ws.py('mk_setuprd.py', mode, capture=True)
    ws.py('mk_chain.py', mode, capture=True)
    ws.py('mk_kernel.py', capture=True)     # after mk_chain: replaces its stock kernel/TXM with the patched ones

def setup_boot(ws, mode):
    """Boot the setup ramdisk and follow rdsetup on the UART. Returns the captured bytes."""
    ser = serial_source(ws.p('logs', f'setup-{mode}-{time.strftime("%Y%m%d-%H%M%S")}.log'))
    if not isinstance(ser, SerialFileTail) and not ser.available():
        die("no serial port of the pwned-DFU board (/dev/cu.usbmodem*) - needed to read the setup result.\n"
            "    (if another program owns the UART: DUALBOOT_SERIAL_LOG=<its log file>)")
    say("boot setup ramdisk ...")
    r = run(sys.executable, os.path.join(LIB, 'boot_chain.py'), env=ws.env(), check=False)
    if r.returncode:
        die("sending the setup chain failed - put the phone back into pwned DFU and retry")
    done = [b'SETUP DONE', b'SETUP FAILED'] if mode == 'install' else [b'REMOVE DONE', b'REMOVE FAILED']
    say(f"waiting for rdsetup ({'create DataB + copy data + read the APTicket' if mode == 'install' else 'delete DataB'}) "
        "- this can take a few minutes ...")
    last = [0.0]
    def progress(buf):
        if time.time() - last[0] > 30:
            last[0] = time.time(); print("   ... ", (buf[-120:].decode('latin1').strip().splitlines() or [''])[-1][:110])
    hit = ser.wait_for(done, timeout=1800, progress=progress)
    if hit is None:
        die("no rdsetup result on the UART after 30 minutes")
    for l in ser.buf.decode('latin1').splitlines():
        if '[rdsetup]' in l and 'TICKET' not in l and 'TKT' not in l:
            print('    ' + l.strip()[:150])
    if hit.endswith(b'FAILED'):
        die("rdsetup reported an error (see above) - nothing else was changed")
    return ser.buf

def cmd_install(a):
    bad = host_check()
    if bad:
        die("the Mac is missing tools - run ./setup.sh first:\n      " + "\n      ".join(bad))
    sel = load_selected()
    if sel.get('build') and not getattr(a, 'build', None) and not a.skip_precheck:
        prof = find_profile(sel.get('board') or pick_board(), sel['build'])
        if not (prof and (prof.get('precheck') or {}).get('ok')):
            say(f"pre-check iOS {sel.get('version', '')} ({sel['build']}) before touching the phone ...")
            if not run_precheck(sel.get('board') or pick_board(), sel['build'], sel.get('ipsw') or None):
                die("pre-check failed - nothing was done on the phone (use --skip-precheck to override)")
    q = wait_dfu(pwned=True)
    board = board_of(q) or die(f"unsupported device CPID {q.get('CPID')} BDID {q.get('BDID')}")
    sel = load_selected()
    sel = sel if sel.get('board', board) == board else {}
    build = getattr(a, 'build', None) or sel.get('build')
    if not build:
        ch = version_choices(board) or die("no versions available (network?) - use --build or --ipsw")
        for i, (_, _, label) in enumerate(ch):
            print(f"   {i + 1}. {label}")
        build = ch[int(input("   which number is the iOS installed on the phone? ")) - 1][0]
    ver = sel.get('version', '') if sel.get('build') == build else \
        next((v for b, v, _ in version_choices(board) if b == build), '')
    given_ipsw = getattr(a, 'ipsw', None) or (sel.get('ipsw') or None if sel.get('build') == build else None)
    prof = ensure_profile(board, build, ver, given_ipsw)
    say(f"iPhone ECID {q['ECID']}  {board}  -> profile iOS {prof['version']} ({prof['build']})"
        f"{'' if prof.get('tested') else '  [NOT DEVICE-TESTED]'}")
    say("2nd Data shares the System volume with stock iOS, so the phone MUST be running iOS "
        f"{prof['version']} ({prof['build']}). The setup boot checks this again.")
    ws = Workspace(q['ECID'], prof)
    if ws.state.get('installed') and not ask("This phone already has 2nd Data. Run the installer again (DataB is kept)?"):
        return
    ws.state.update(board=prof['board'], build=prof['build']); ws.save()
    ipsw = find_ipsw(prof, given_ipsw); say(f"IPSW: {ipsw}")
    extract_ipsw(ws, ipsw)
    prepare_rootfs(ws, ipsw)
    complete_profile(ws)
    prepare_tickets(ws)
    prepare_iboot(ws)
    say("build setup chain ..."); build_setup_chain(ws, 'install')
    q = wait_dfu(pwned=True)
    buf = setup_boot(ws, 'install')
    import re
    m = re.search(rb'SYSBUILD (\S+) SYSVER (\S+)', buf)
    if not m or m.group(1).decode() != prof['build']:
        die(f"the phone runs {m.group(1).decode() if m else '?'} - does not match profile {prof['build']}. "
            "Stopping (DataB was created but is unused; remove it with ./dualboot.py remove).")
    tkt, d = parse_ticket(buf)
    if tkt is None:
        die(f"could not rebuild the APTicket from the UART ({d}) - run install again (DataB is kept)")
    open(ws.p('out/apticket.installed.der'), 'wb').write(tkt)
    say(f"installed APTicket: {d[:16]}... ({len(tkt)} bytes)")
    ws.state['setup'] = time.strftime('%Y-%m-%d %H:%M:%S'); ws.save()
    say("build 2nd Data ...")
    ensure_daemons(ws); build_osb(ws)
    ws.state['installed'] = True; ws.save()
    say("Setup done. Hold the buttons to reset the phone, then put it back into pwned DFU for the first 2nd Data boot.")
    q = wait_dfu(pwned=True)
    a.no_wait = True
    cmd_boot(a)
    say("First boot: jbloader installs the bootstrap, SSH and activation (~2-3 minutes) ...")
    udid = None
    for _ in range(150):
        udid = device_udid(q['ECID'])
        if udid: break
        time.sleep(2)
    if not udid or not SSH(ws, udid).wait(timeout=900):
        die("2nd Data did not come up on SSH - check the screen (verbose boot). Once it is up, run: ./dualboot.py provision")
    a.ecid = q['ECID']
    cmd_provision(a)
    say("DONE. Finish Setup on the phone (Wi-Fi, Apple ID ...). Reboot = stock iOS; 2nd Data again: pwned DFU -> ./boot.sh")
    warn("If the phone shows 'iPhone Partially Set Up': tap 'Continue with Partial Setup'. "
         "NEVER 'Erase and Start Over'.")

def cmd_remove(a):
    q = wait_dfu(pwned=True)
    cands = [(d, s) for d, s in workspaces_for(q['ECID']) if s.get('build')]
    if not cands:
        die("no workspace for this phone (the setup ramdisk needs the IPSW + ticket) - run install first or "
            "use the Mac it was installed from")
    d, s = cands[-1]
    ws = Workspace(q['ECID'], find_profile(s['board'], s['build']))
    if not ask("REMOVE 2nd Data: delete the DataB volume (all 2nd Data data) and the tool's ob folder in Preboot. "
               "Stock iOS is untouched. Continue?"):
        return
    if not os.path.exists(ws.p('build/ipsw/BuildManifest.plist')):
        extract_ipsw(ws, find_ipsw(ws.profile, getattr(a, 'ipsw', None)))
    prepare_tickets(ws); prepare_iboot(ws)
    say("build setup chain (remove) ..."); build_setup_chain(ws, 'remove')
    q = wait_dfu(pwned=True)
    setup_boot(ws, 'remove')
    ws.state.update(installed=False, provisioned=None, removed=time.strftime('%Y-%m-%d %H:%M:%S')); ws.save()
    say("2nd Data removed. Hold the buttons to reset the phone -> stock iOS boots normally.")

# ------------------------------------------------------------------------------------------- provision
DAEMONS = [  # mkdaemon name, stock program, weak dylib (OS B fix loaded into the daemon)
    ('ctkd', '/System/Library/Frameworks/CryptoTokenKit.framework/ctkd', None),
    ('coreauthd', '/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd',
     '/private/preboot/Cryptexes/ob/ca.dylib'),
    ('commcenter', '/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter',
     '/private/var/wireless/Library/obfdr.dylib'),
    ('securityd', '/usr/libexec/securityd', '/private/var/Keychains/obkeychain.dylib'),
    ('lockdownd', '/usr/libexec/lockdownd', '/private/var/root/Library/Lockdown/obpair.dylib'),
    ('mobileactivationd', '/usr/libexec/mobileactivationd', None),
]
JOBS = ['com.apple.CommCenter', 'com.apple.CoreAuthentication.daemon', 'com.apple.ctkd', 'com.apple.mobile.lockdown',
        'com.apple.securityd']

def ensure_daemons(ws):
    """Patched daemon copies + job plists in <ws>/build/daemons (rebuilt from the rootfs when it is available)."""
    have_rootfs = os.path.exists(ws.p('rootfs/usr/libexec/securityd'))
    os.makedirs(ws.p('build/daemons'), exist_ok=True)
    for name, path, weak in DAEMONS:
        if have_rootfs:
            ws.py('mkdaemon.py', name, path, *(['--weak-dylib', weak] if weak else []), capture=True)
        elif not os.path.exists(ws.p('build/daemons', name)):
            die(f"{name} is missing and there is no rootfs ({ws.p('rootfs')}) to build it from")
    wd = ws.p('build/daemons/com.apple.watchdogd.plist')
    if have_rootfs:
        import plistlib
        c = plistlib.load(open(ws.p('rootfs/System/Library/xpc/launchd.plist'), 'rb'))
        j = dict(c['LaunchDaemons']['/System/Library/LaunchDaemons/com.apple.watchdogd.plist'])
        for k in ('KeepAlive', 'LaunchEvents', '_PanicOnCrash'):
            j.pop(k, None)
        plistlib.dump(j, open(wd, 'wb'), fmt=plistlib.FMT_XML)
    elif not os.path.exists(wd):
        die("com.apple.watchdogd.plist is missing and there is no rootfs")

def build_stage(ws):
    st = ws.p('build/stage')
    shutil.rmtree(st, ignore_errors=True)
    for d in ('boot', 'device', 'pkgs', 'daemons', 'jobs', 'scripts'):
        os.makedirs(os.path.join(st, d))
    shutil.copy2(os.path.join(PAYLOAD, 'boot/obhook.dylib'), os.path.join(st, 'boot'))
    for sub in ('device', 'pkgs'):
        for f in os.listdir(os.path.join(PAYLOAD, sub)):
            shutil.copy2(os.path.join(PAYLOAD, sub, f), os.path.join(st, sub, f))
    for name in ('ctkd', 'coreauthd', 'commcenter', 'securityd', 'lockdownd'):
        shutil.copy2(ws.p('build/daemons', name), os.path.join(st, 'daemons', name))
    for l in JOBS + ['com.apple.watchdogd']:
        shutil.copy2(ws.p('build/daemons', l + '.plist'), os.path.join(st, 'jobs', l + '.plist'))
    shutil.copy2(os.path.join(PAYLOAD, 'boot/com.apple.mobileactivationd.plist'), os.path.join(st, 'jobs'))
    for f in ('osb-boot.sh', 'jbjob.sh', 'obhook-restart.sh', 'uicache.wrapper.sh'):
        shutil.copy2(os.path.join(ROOT, 'device', f), os.path.join(st, 'scripts', f))
    shutil.copy2(os.path.join(ROOT, 'device/provision.sh'), st)
    return st

def ssh_argv(ssh):
    return ['ssh', *ssh._base(), '-p', str(2222), 'root@localhost']

def stream_tar(ssh, src_dir, names, dest, extra_tar=()):
    """tar src_dir/names | ssh 'tar -x -C dest' (no temp files on either side)."""
    ssh._iproxy()
    tar = subprocess.Popen(['tar', *extra_tar, '-C', src_dir, '-cf', '-', *names], stdout=subprocess.PIPE)
    rc = subprocess.run(ssh_argv(ssh) + ['-o', 'Compression=no', f'mkdir -p {dest} && tar -C {dest} -xpf - 2>/dev/null; echo done'],
                        stdin=tar.stdout, capture_output=True, text=True)
    tar.wait()
    return rc.returncode == 0 and 'done' in rc.stdout

def connect_osb(ecid=None):
    ws = only_installed_ws(ecid)
    udid = device_udid(ws.ecid) or die("no iPhone on USB - is 2nd Data booted?")
    ssh = SSH(ws, udid)
    if not ssh.wait(timeout=120):
        die("cannot SSH into 2nd Data (wait until it has booted, then retry)")
    return ws, ssh

def install_system_apps(ws, ssh):
    n = ssh.run('ls -d /private/var/containers/Bundle/Application/*/*.app 2>/dev/null | wc -l', check=False).stdout.strip()
    n = int(n or 0)
    if n >= 20:
        say(f"system apps: already installed ({n})"); return
    on_dev = ssh.run('ls /private/var/staged_system_apps 2>/dev/null | wc -l', check=False).stdout.strip()
    if int(on_dev or 0) == 0:          # rdsetup copies them into DataB at install; fall back to the rootfs copy
        staged = ws.p('rootfs/private/var/staged_system_apps')
        if not os.path.isdir(staged):
            warn("neither the phone nor the rootfs has staged_system_apps - skipping system apps"); return
        say("system apps: copying staged_system_apps (~1.2 GB) ...")
        if not stream_tar(ssh, ws.p('rootfs/private/var'), ['staged_system_apps'], '/private/var',
                          extra_tar=('--uid', '0', '--gid', '0')):
            warn("copying staged_system_apps failed"); return
    say("system apps: installing with SystemAppMigrator (~5 minutes) ...")
    ssh.run('/var/jb/usr/bin/sysapps', check=False, timeout=1200)
    n = ssh.run('ls -d /private/var/containers/Bundle/Application/*/*.app 2>/dev/null | wc -l', check=False).stdout.strip()
    say(f"system apps: {n} apps"); ssh.run('killall -9 SpringBoard', check=False)

def pair_with_mac(ws, ssh):
    r = run('idevicepair', '-u', ssh.udid, 'validate', check=False, capture=True)
    if r.returncode == 0:
        say("the Mac is paired with 2nd Data"); return
    run('idevicepair', '-u', ssh.udid, 'pair', check=False, capture=True)
    say("On the iPhone: tap 'Trust' (do not touch anything else while the alert is up)")
    for _ in range(3):
        if sys.stdin.isatty():
            input("   -> press Enter after tapping Trust ")
        else:
            time.sleep(20)
        r = run('idevicepair', '-u', ssh.udid, 'pair', check=False, capture=True)
        if 'SUCCESS' in (r.stdout + r.stderr):
            say("pair OK"); return
        warn((r.stdout + r.stderr).strip())
        if 'denied' in (r.stdout + r.stderr):
            ssh.run('launchctl kickstart -k system/com.apple.mobile.lockdown', check=False)
            run('idevicepair', '-u', ssh.udid, 'pair', check=False, capture=True)
    warn("pairing not finished - redo it later with: idevicepair pair")

def cmd_provision(a):
    ws, ssh = connect_osb(getattr(a, 'ecid', None))
    first = not ws.state.get('provisioned')
    say("building the patched daemons ..."); ensure_daemons(ws)
    st = build_stage(ws)
    P = '/var/jb/tmp/dualboot-payload'
    say("uploading the payload ...")
    ssh.run(f'rm -rf {P}', check=False)
    if not stream_tar(ssh, st, ['.'], P):
        die("uploading the payload failed")
    say("installing the fixes on the phone ...")
    r = subprocess.run(ssh_argv(ssh) + [f'/var/jb/usr/bin/zsh {P}/provision.sh {P}'])
    if r.returncode:
        die("provision.sh reported errors - see /var/jb/var/log/dualboot-provision.log on the phone")
    if first or getattr(a, 'apply', False):
        # securityd and lockdownd start from the launchd cache override (/cores/daemons) before provision.sh has put
        # obkeychain/obpair on DataB; their weak load found nothing, so restart them now (securityd first). Without
        # this the first boot has no software keychain and lockdownd answers pairing with MissingValue (-12).
        say("restarting securityd + lockdownd so they load obkeychain/obpair ...")
        ssh.run('launchctl kickstart -k system/com.apple.securityd; sleep 3; '
                'launchctl kickstart -k system/com.apple.mobile.lockdown; sleep 3', check=False)
    install_system_apps(ws, ssh)
    ws.state['provisioned'] = time.strftime('%Y-%m-%d %H:%M:%S'); ws.save()
    if first or getattr(a, 'apply', False):
        say("applying now (osb-boot.sh: swap daemons, activation, enable tweaks, respring) ...")
        ssh.run('nohup /var/jb/usr/bin/zsh /var/jb/usr/libexec/osb-boot.sh >/dev/null 2>&1 &', check=False)
        time.sleep(30)
        pair_with_mac(ws, ssh)
    else:
        say("updated. Daemon/boot changes take effect on the next boot (or run: provision --apply)")
    say("provision: done")

def main():
    ap = argparse.ArgumentParser(prog='dualboot.py', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--no-wait', action='store_true', help="don't wait for SSH after booting")
    sub = ap.add_subparsers(dest='cmd')
    sub.add_parser('boot', help='boot 2nd Data (pwned DFU)').add_argument('--no-wait', action='store_true')
    s = sub.add_parser('install', help='first-time setup'); s.add_argument('--ipsw'); s.add_argument('--build')
    s.add_argument('--skip-precheck', action='store_true')
    s = sub.add_parser('remove', help='delete DataB + Preboot files'); s.add_argument('--ipsw')
    s = sub.add_parser('provision', help='(re)apply userland fixes over SSH'); s.add_argument('--ecid')
    s.add_argument('--apply', action='store_true', help='also run osb-boot.sh now (restarts daemons, respring)')
    sub.add_parser('status'); sub.add_parser('doctor')
    s = sub.add_parser('ssh', help='ssh into 2nd Data'); s.add_argument('--ecid'); s.add_argument('remote', nargs='*')
    sub.add_parser('rebuild', help='rebuild the 2nd Data boot artifacts').add_argument('--ecid')
    s = sub.add_parser('versions', help='iOS versions: local profiles + Apple builds'); s.add_argument('--board')
    s.add_argument('--plain', action='store_true', help=argparse.SUPPRESS)
    s = sub.add_parser('select', help='choose the iOS version installed on the phone')
    s.add_argument('--board', help=BOARD_HELP); s.add_argument('--build'); s.add_argument('--ipsw')
    s.add_argument('--auto', action='store_true', help='read it from the phone (booted into iOS, USB)')
    s.add_argument('--no-precheck', action='store_true', help="don't run the pre-check after selecting")
    s = sub.add_parser('precheck', help='check every patch for a build before touching the phone (ipsw --remote)')
    s.add_argument('--build'); s.add_argument('--board'); s.add_argument('--ipsw')
    s = sub.add_parser('profile', help='generate a version profile from an IPSW (every patch re-resolved)')
    s.add_argument('--ipsw', required=True); s.add_argument('--board', help=BOARD_HELP)
    s.add_argument('--rootfs'); s.add_argument('--force', action='store_true')
    a = ap.parse_args()
    {'boot': cmd_boot, 'install': cmd_install, 'remove': cmd_remove, 'provision': cmd_provision,
     'status': cmd_status, 'doctor': cmd_doctor, 'ssh': cmd_ssh, 'rebuild': cmd_rebuild,
     'versions': cmd_versions, 'select': cmd_select, 'profile': cmd_profile, 'precheck': cmd_precheck,
     None: cmd_auto}[a.cmd](a)

if __name__ == '__main__':
    main()
