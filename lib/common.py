"""Shared helpers for dualboot.py: host checks, device (irecovery/usb) detection, workspace, serial capture, ssh."""
import glob, json, os, select, shutil, subprocess, sys, termios, time

LIB = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(LIB)                      # the dualboot/ folder
DUALBOOT = LIB                                   # build/boot scripts live next to this module
PROFILES = os.path.join(ROOT, 'profiles')
PAYLOAD = os.path.join(ROOT, 'payload')
DEVICE = os.path.join(ROOT, 'device')            # scripts installed on the phone
WORKROOT = os.environ.get('DUALBOOT_HOME') or os.path.expanduser('~/dualboot-work')
USBLITER8CTL = os.environ.get('USBLITER8CTL') or os.path.join(ROOT, 'tools/usbliter8ctl')

# ----------------------------------------------------------------------------------------------- output
def say(msg):  print(f"\033[1;36m[dualboot]\033[0m {msg}", flush=True)
def warn(msg): print(f"\033[1;33m[dualboot] !\033[0m {msg}", flush=True)
def die(msg):
    print(f"\033[1;31m[dualboot] x\033[0m {msg}", flush=True)
    sys.exit(1)

def run(*a, check=True, env=None, capture=False, cwd=None, timeout=None):
    r = subprocess.run([str(x) for x in a], env=env, cwd=cwd, timeout=timeout,
                       capture_output=capture, text=True)
    if check and r.returncode:
        die(f"{' '.join(map(str, a))} -> exit {r.returncode}\n{(r.stdout or '')[-2000:]}{(r.stderr or '')[-2000:]}")
    return r

def ask(prompt, default=False):
    if os.environ.get('DUALBOOT_YES') == '1':
        return True
    s = input(f"\033[1;35m[dualboot] ?\033[0m {prompt} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not s else s in ('y', 'yes')

# ----------------------------------------------------------------------------------------------- host
HOST_TOOLS = {
    'irecovery': 'brew install libirecovery (or libimobiledevice)',
    'iproxy': 'brew install libimobiledevice',
    'idevicepair': 'brew install libimobiledevice',
    'ldid': 'brew install ldid',
    'ipsw': 'brew install blacktop/tap/ipsw',
    'codesign': 'Xcode command line tools',
    'hdiutil': 'macOS',
    'otool': 'Xcode command line tools',
    'python3': 'brew install python@3',
}

def host_check(need_ipsw=True):
    bad = []
    for t, hint in HOST_TOOLS.items():
        if t == 'ipsw' and not need_ipsw:
            continue
        if not shutil.which(t):
            bad.append(f"{t}  ({hint})")
    for mod, hint in (('pyimg4', 'pip3 install pyimg4'), ('usb', 'pip3 install pyusb  (+ brew install libusb)')):
        try:
            __import__(mod)
        except ImportError:
            bad.append(f"python module {mod}  ({hint})")
    if not os.path.exists(USBLITER8CTL):
        bad.append(f"usbliter8ctl at {USBLITER8CTL} (set USBLITER8CTL)")
    return bad

# ----------------------------------------------------------------------------------------------- device
APPLE_DFU_RECOVERY = (0x1227, 0x1280, 0x1281, 0x1282, 0x1283)    # USB product IDs: DFU, Recovery (iBoot)

def dfu_or_recovery_on_usb():
    """An Apple device in DFU or Recovery is on USB (pyusb enumerates in ~20 ms; `irecovery -q` itself waits ~6 s for a
    device when there is none, which made every menu and wait loop slow)."""
    try:
        import usb.core
        return usb.core.find(idVendor=0x05ac, custom_match=lambda d: d.idProduct in APPLE_DFU_RECOVERY) is not None
    except Exception:
        return True                  # cannot tell: let irecovery decide

def irec_query():
    if not dfu_or_recovery_on_usb():
        return None
    r = subprocess.run(['irecovery', '-q'], capture_output=True, text=True)
    if r.returncode:
        return None
    d = {}
    for l in r.stdout.splitlines():
        if ':' in l:
            k, v = l.split(':', 1)
            d[k.strip()] = v.strip()
    return d or None

def wait_dfu(pwned=True, timeout=None):
    """Block until a device in DFU shows up (pwned DFU if pwned=True)."""
    t0 = time.time(); shown = False
    while True:
        q = irec_query()
        if q and q.get('MODE') == 'DFU' and (not pwned or 'usbliter8' in q.get('PWND', '')):
            return q
        if not shown:
            say("waiting for the iPhone in pwned DFU ...")
            shown = True
        if timeout and time.time() - t0 > timeout:
            die("timed out waiting for pwned DFU")
        time.sleep(1)

# A13 (T8030, CPID 0x8030) boards: iPhone 11 / 11 Pro / 11 Pro Max, iPhone SE (2nd gen), iPad (9th gen) Wi-Fi /
# Cellular. Values from the IPSW BuildManifests (ApBoardID).
A13_BOARDS = {0x04: 'n104ap', 0x06: 'd421ap', 0x02: 'd431ap', 0x10: 'd79ap', 0x18: 'j181ap', 0x1A: 'j182ap'}
BOARD_PRODUCTS = {'n104ap': 'iPhone12,1', 'd421ap': 'iPhone12,3', 'd431ap': 'iPhone12,5', 'd79ap': 'iPhone12,8',
                  'j181ap': 'iPad12,1', 'j182ap': 'iPad12,2'}
BOARD_HELP = 'n104ap | d421ap | d431ap | d79ap | j181ap | j182ap (default: the connected device)'

def _hex(v):
    try: return int(str(v), 16)
    except ValueError: return None

def board_of(q):
    """(cpid, bdid) from irecovery -q -> board name (a profile's, else the A13 table)."""
    cpid, bdid = _hex(q.get('CPID', '')), _hex(q.get('BDID', ''))
    for p in list_profiles():
        if _hex(p['cpid']) == cpid and _hex(p.get('bdid', '')) == bdid:
            return p['board']
    return A13_BOARDS.get(bdid) if cpid == 0x8030 else None

# ----------------------------------------------------------------------------------------------- profiles
def list_profiles():
    out = []
    for d in sorted(os.listdir(PROFILES)) if os.path.isdir(PROFILES) else []:
        f = os.path.join(PROFILES, d, 'profile.json')
        if os.path.exists(f):
            p = json.load(open(f)); p['dir'] = os.path.join(PROFILES, d); p['name'] = d
            out.append(p)
    return out

def find_profile(board, build):
    for p in list_profiles():
        if p['board'] == board and p['build'] == build:
            return p
    return None

# ----------------------------------------------------------------------------------------------- workspace
class Workspace:
    """~/dualboot-work/<ECID>-<build>: everything device-specific (tickets, builds, ssh key, logs)."""
    def __init__(self, ecid, profile):
        self.ecid = ecid.lower().replace('0x', '').zfill(16)
        self.profile = profile
        self.root = os.path.join(WORKROOT, f"{self.ecid}-{profile['build']}")
        for d in ('out', 'build', 'build/ipsw', 'logs'):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        self.state_file = os.path.join(self.root, 'state.json')
        self.state = json.load(open(self.state_file)) if os.path.exists(self.state_file) else {}

    def p(self, *a): return os.path.join(self.root, *a)
    def save(self): json.dump(self.state, open(self.state_file, 'w'), indent=1)

    def env(self, **extra):
        e = dict(os.environ)
        e.update(OSB_WORK=self.p('build'), OSB_OUT=self.p('out'), OSB_IPSW=self.p('build/ipsw'),
                 OSB_PROFILE=self.profile['dir'], OSB_BOARD=self.profile['board'],
                 OSB_TICKET=self.p('out/apticket.installed.der'), OSB_ROOTFS=self.p('rootfs'),
                 OSB_PREBUILT=os.path.join(PAYLOAD, 'boot'), USBLITER8CTL=USBLITER8CTL)
        e.update({k: str(v) for k, v in extra.items()})
        return e

    def py(self, script, *args, **kw):
        return run(sys.executable, os.path.join(DUALBOOT, script), *args, env=self.env(), **kw)

# ----------------------------------------------------------------------------------------------- serial
SERIAL_GLOB = os.environ.get('OSB_SERIAL') or '/dev/cu.usbmodem*'

class Serial:
    """Raw 115200 8N1 reader for the pwned-DFU board's UART bridge; reconnects if the board re-enumerates."""
    def __init__(self, logpath):
        self.log = open(logpath, 'ab', buffering=0); self.fd = None; self.buf = b''

    def _open(self):
        for port in sorted(glob.glob(SERIAL_GLOB)):
            try:
                fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
                a = termios.tcgetattr(fd)
                a[0] = 0; a[1] = 0; a[3] = 0
                a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
                a[4] = a[5] = termios.B115200
                termios.tcsetattr(fd, termios.TCSANOW, a)
                self.fd, self.port = fd, port
                self.log.write(f"\n==== dualboot serial open {port} {time.ctime()} ====\n".encode())
                return True
            except OSError:
                pass
        return False

    def available(self):
        return bool(glob.glob(SERIAL_GLOB))

    def pump(self, secs=1.0):
        """Read for up to secs; returns the new bytes."""
        if self.fd is None and not self._open():
            time.sleep(secs); return b''
        try:
            r, _, _ = select.select([self.fd], [], [], secs)
            if r:
                d = os.read(self.fd, 65536)
                if not d:
                    raise OSError('eof')
                self.log.write(d); self.buf += d
                return d
        except (OSError, BlockingIOError):
            try: os.close(self.fd)
            except OSError: pass
            self.fd = None
        return b''

    def wait_for(self, needles, timeout, progress=None):
        """Pump until one of needles (bytes) appears in the accumulated buffer; returns it or None."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            self.pump(1.0)
            for n in needles:
                if n in self.buf:
                    return n
            if progress:
                progress(self.buf)
        return None

# ----------------------------------------------------------------------------------------------- ssh
SSH_PORT = int(os.environ.get('OSB_SSH_PORT', '2222'))

class SSH:
    def __init__(self, ws, udid):
        self.ws, self.udid = ws, udid
        self.key = ws.p('out/osb_ssh/id_ed25519')

    def _iproxy(self):
        if subprocess.run(['pgrep', '-f', f'iproxy -u {self.udid} {SSH_PORT} 22'], capture_output=True).returncode:
            subprocess.run(['pkill', '-f', f'iproxy.* {SSH_PORT} 22'], capture_output=True)
            subprocess.Popen(['iproxy', '-u', self.udid, str(SSH_PORT), '22'],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)

    def _base(self):
        return ['-i', self.key, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=15']

    def run(self, cmd, check=True, timeout=600):
        self._iproxy()
        return run('ssh', *self._base(), '-p', SSH_PORT, 'root@localhost', cmd, check=check, capture=True,
                   timeout=timeout)

    def put(self, src, dst, check=True):
        self._iproxy()
        return run('scp', '-r', *self._base(), '-P', SSH_PORT, src, f'root@localhost:{dst}', check=check,
                   capture=True)

    def wait(self, timeout=600):
        t0 = time.time()
        while time.time() - t0 < timeout:
            self._iproxy()
            r = subprocess.run(['ssh', *self._base(), '-p', str(SSH_PORT), 'root@localhost', 'echo ok'],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and 'ok' in r.stdout:
                return True
            time.sleep(5)
        return False

def device_udid(ecid):
    """usbmuxd UDID for this ECID (A12+: <CPID 8 hex>-<ECID 16 hex>)."""
    r = subprocess.run(['idevice_id', '-l'], capture_output=True, text=True)
    e = ecid.lower().replace('0x', '').zfill(16)
    for l in r.stdout.split():
        if l.lower().endswith(e):
            return l
    return None

# ----------------------------------------------------------------------------------------------- serial (file)
class SerialFileTail:
    """Same interface as Serial, but follows a log file another UART logger is writing (the port can only have one
    reader). Set DUALBOOT_SERIAL_LOG=/path/to/log to use it."""
    def __init__(self, path):
        self.f = open(path, 'rb'); self.f.seek(0, 2); self.buf = b''

    def available(self): return True

    def pump(self, secs=1.0):
        d = self.f.read()
        if d:
            self.buf += d; return d
        time.sleep(secs); return b''

    def wait_for(self, needles, timeout, progress=None):
        t0 = time.time()
        while time.time() - t0 < timeout:
            self.pump(1.0)
            for n in needles:
                if n in self.buf:
                    return n
            if progress:
                progress(self.buf)
        return None

def serial_source(logpath):
    ext = os.environ.get('DUALBOOT_SERIAL_LOG')
    if ext:
        return SerialFileTail(ext)
    return Serial(logpath)

# ----------------------------------------------------------------------------------------------- ticket from UART
def parse_ticket(log_bytes):
    """Rebuild the APTicket rdsetup dumped as 'TKT <off> <hex> <crc32>' lines (CRC-checked, several passes).
    Returns (ticket_bytes, dir_hash) or (None, reason)."""
    import binascii, hashlib, re
    log = log_bytes.decode('latin1')
    heads = re.findall(r'TICKET dir=([0-9A-Fa-f]{96}) len=(\d+) sha384=([0-9A-F]{96}) crc=([0-9a-f]{8})', log)
    if not heads:
        return None, 'no TICKET header'
    chunks = {}
    for off, hx, crc in re.findall(r'TKT ([0-9a-f]{5}) ([0-9a-f]{2,96}) ([0-9a-f]{8})', log):
        if len(hx) % 2:
            continue
        b = bytes.fromhex(hx)
        if binascii.crc32(b) == int(crc, 16):
            chunks.setdefault(int(off, 16), b)
    d, n, sha, _ = heads[-1]
    n = int(n)
    data = b''.join(chunks.get(o, b'') for o in range(0, n, 48))
    if len(data) == n and hashlib.sha384(data).hexdigest().upper() == sha:
        return data, d
    missing = [hex(o) for o in range(0, n, 48) if o not in chunks]
    return None, f"incomplete ticket ({len(missing)} chunks missing)"
