"""Central configuration for the dual-boot build scripts.

Every path and firmware file name the build scripts use comes from here. dualboot.py (lib/common.py) sets the
variables below to a per-device work directory and a version profile; the defaults only apply when a script is
run by hand.

  OSB_WORK     build root            (default: lib/build)
  OSB_OUT      tickets, iBoot raws, ssh key, rsep (default: out/)
  OSB_IPSW     extracted IPSW dir     (default: $OSB_WORK/ipsw)
  OSB_PROFILE  version profile dir    (default: resolver records in lib/osb, our own patches in patches/)
  OSB_BOARD    device class           (default: d421ap)
  OSB_TICKET   installed APTicket     (default: $OSB_OUT/apticket.installed.der)
  OSB_ROOTFS   stock binaries/launchd.plist source for mkdaemon (default: <workspace>/rootfs)
"""
import os, plistlib

HERE = os.path.dirname(os.path.abspath(__file__))
JB = os.path.dirname(HERE)

WORK = os.environ.get('OSB_WORK') or os.path.join(HERE, 'build')
OUT = os.environ.get('OSB_OUT') or os.path.join(JB, 'out')
IPSW = os.environ.get('OSB_IPSW') or os.path.join(WORK, 'ipsw')
PROFILE = os.environ.get('OSB_PROFILE') or ''
BOARD = os.environ.get('OSB_BOARD') or 'd421ap'
TICKET = os.environ.get('OSB_TICKET') or os.path.join(OUT, 'apticket.installed.der')
ROOTFS = os.environ.get('OSB_ROOTFS') or os.path.join(os.path.dirname(WORK), 'rootfs')
# 2nd iOS (developing feature): build the OS B artifacts for its own System volume (OS2System) and Data volume
# (OS2Data) instead of the stock System + DataB. OS2_SYSDEV is OS2System's BSD name as os2vol reported it.
OS2 = os.environ.get('OSB_OS2') == '1'
OS2_SYSDEV = os.environ.get('OSB_OS2_SYSDEV', '')

def arm64e_arch(path):
    """['--arch', 'arm64e'] for a fat binary with an arm64e slice (what the phone's arm64e processes load), else [].
    Plain `codesign -d` reports the slice of the Mac's own CPU: arm64e on Apple Silicon, but the first slice (arm64)
    on an Intel Mac - a trust cache built there would carry the wrong CDHash (payload/boot/obhook.dylib is fat)."""
    import struct
    h = open(path, 'rb').read(8 + 20 * 16)
    if len(h) < 8 or struct.unpack_from('>I', h)[0] != 0xcafebabe:
        return []
    n = min(struct.unpack_from('>I', h, 4)[0], 16)
    slices = [struct.unpack_from('>II', h, 8 + 20 * i) for i in range(n)]
    return ['--arch', 'arm64e'] if any(ct == 0x0100000c and st & 0xffffff == 2 for ct, st in slices) else []

# record files: a profile keeps everything in one directory; without one, resolver plans are read from lib/osb and
# our own patches from patches/
REC = PROFILE or os.path.join(HERE, 'osb')
PATCHES = PROFILE or os.path.join(JB, 'patches')
rec = lambda n: os.path.join(REC, n)
patch = lambda n: os.path.join(PATCHES, n)
work = lambda *p: os.path.join(WORK, *p)
out = lambda *p: os.path.join(OUT, *p)

_LEGACY = {  # 24B119 / d421ap names, used when the IPSW dir has no BuildManifest.plist (hand-extracted tree)
    'ANE': 'Firmware/ane/h12_ane_fw_metis.im4p',
    'AOP': 'Firmware/AOP/aopfw-iphone12aop.RELEASE.im4p',
    'AVE': 'Firmware/ave/AppleAVE2FW_H12.im4p',
    'Ap,SecurePageTableMonitor': 'Firmware/sptm.t8030.release.im4p',
    'Ap,TrustedExecutionMonitor': 'Firmware/txm.iphoneos.release.im4p',
    'GFX': 'Firmware/agx/armfw_g12p.im4p',
    'ISP': 'Firmware/isp_bni/adc-zelus-d4x.im4p',
    'PMP': 'Firmware/pmp/t8030pmp.im4p',
    'StaticTrustCache': 'Firmware/141-09290-215.dmg.aea.trustcache',
    'SIO': 'Firmware/SmartIOFirmware_ASCv2.im4p',
    'WCHFirmwareUpdater': 'Firmware/WirelessPower/WirelessPower.iphone12.im4p',
    'KernelCache': 'kernelcache.release.iphone12',
    'DeviceTree': 'Firmware/all_flash/DeviceTree.d421ap.im4p',
    'iBEC': 'Firmware/dfu/iBEC.d421.RELEASE.im4p',
    'iBSS': 'Firmware/dfu/iBSS.d421.RELEASE.im4p',
    'RestoreRamDisk': '141-10399-240.dmg',
    'RestoreTrustCache': 'Firmware/141-10399-240.dmg.trustcache',
    'RestoreSEP': 'Firmware/all_flash/sep-firmware.d421.RELEASE.im4p',
}

def _identity():
    bm = os.path.join(IPSW, 'BuildManifest.plist')
    if not os.path.exists(bm):
        return None
    m = plistlib.load(open(bm, 'rb'))
    ids = [b for b in m['BuildIdentities'] if b['Info'].get('DeviceClass', '').lower() == BOARD.lower()]
    erase = [b for b in ids if b['Info'].get('RestoreBehavior') == 'Erase']
    if not (erase or ids):
        raise SystemExit(f"!! BuildManifest has no identity for {BOARD}")
    return (erase or ids)[0]

_ID = _identity()

def comp(key):
    """IPSW-relative path of a BuildManifest component for this board."""
    if _ID is None:
        return _LEGACY[key]
    p = _ID['Manifest'].get(key, {}).get('Info', {}).get('Path')
    if not p:
        raise SystemExit(f"!! BuildManifest identity for {BOARD} has no {key}")
    return p

def ipsw(key):
    return os.path.join(IPSW, comp(key))

# firmware the bootx chains pass through (restore order; RestoreLogo skipped): (manifest key, img4 name, fourcc)
FIRMWARE_KEYS = [
    ('ANE', 'ANE.img4', 'anef'),
    ('AOP', 'AOP.img4', 'aopf'),
    ('AVE', 'AVE.img4', 'avef'),
    ('Ap,SecurePageTableMonitor', 'SPTM.img4', 'sptm'),
    ('Ap,TrustedExecutionMonitor', 'TXM.img4', None),
    ('GFX', 'GFX.img4', 'gfxf'),
    ('ISP', 'ISP.img4', 'ispf'),
    ('PMP', 'PMP.img4', 'pmpf'),
    ('StaticTrustCache', 'StaticTrustCache.img4', 'trst'),
    ('SIO', 'SIO.img4', 'siof'),
    ('WCHFirmwareUpdater', 'WCH.img4', 'wchf'),
    ('KernelCache', 'Kernelcache.img4', 'rkrn'),
]

def has(key):
    """The board's BuildManifest identity lists this component (iPads have no WCHFirmwareUpdater)."""
    return _ID is None or bool(_ID['Manifest'].get(key, {}).get('Info', {}).get('Path'))

def firmware():
    """[(ipsw-relative path, img4 name, fourcc)], the layout mk_chain.FIRMWARE uses (components the board lacks are
    left out)."""
    return [(comp(k), o, f) for k, o, f in FIRMWARE_KEYS if has(k)]
