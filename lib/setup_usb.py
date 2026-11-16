import binascii
import hashlib
import re
import socket
import subprocess
import tempfile
import time

from setup_ticket import SetupError, inspect_setup_log, select_ticket


LOCAL_PORT = 23330
REMOTE_PORT = 2233
MAX_TRANSCRIPT = 8 * 1024 * 1024


def relay_serial(ecid, mode):
    if mode not in ('install', 'remove', 'probe'):
        raise ValueError(f'unknown setup mode: {mode}')
    return f'doublera1n-{mode}-{int(ecid, 16):016x}'


def read_snapshot(port=LOCAL_PORT, *, probe=False):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as conn:
        conn.settimeout(10)
        stream = conn.makefile('rb')
        line = stream.readline(96)
        if not line:
            raise ConnectionError('USB relay is not answering yet')
        prefix = b'DBPROBE1' if probe else b'DBUSB1'
        match = re.fullmatch(prefix + rb' (\d+) (\d+) ([01])\n', line)
        if not match:
            raise SetupError('USB setup relay sent an invalid header')
        old_len, now_len, overflow = (int(value) for value in match.groups())
        if overflow:
            raise SetupError('USB setup relay transcript overflowed before completion')
        if old_len > 65536 or now_len > MAX_TRANSCRIPT:
            raise SetupError('USB setup relay sent an oversized transcript')
        data = stream.read(old_len + now_len + 1)
        if len(data) != old_len + now_len:
            raise ConnectionError('USB setup relay connection ended during a snapshot')
        return (data[:old_len] or None, data[old_len:])


def _plain(transcript):
    return re.sub(rb'(?m)^\[rdsetup\] ', b'', transcript)


def ticket_from_transcript(initial_log, transcript, ecid, profile):
    plain = _plain(transcript)
    headers = inspect_setup_log(initial_log if initial_log is not None else plain,
                                profile['build'], plain if initial_log is not None else None)
    candidates = {}
    for directory, length, digest, _ in headers:
        header = re.search(rf'(?m)^TICKET dir={directory} len={length} sha384={digest} crc=[0-9A-Fa-f]{{8}}$',
                           plain.decode('latin1'), re.I)
        if header is None:
            continue
        end = re.search(rf'(?m)^TICKET END {digest}$', plain.decode('latin1')[header.end():], re.I)
        if end is None:
            continue
        segment = plain[header.end():header.end() + end.start()]
        chunks = {}
        for offset, hexdata, crc in re.findall(rb'(?m)^TKT ([0-9a-f]{5}) ([0-9a-f]{2,96}) ([0-9a-f]{8})$', segment):
            block = bytes.fromhex(hexdata.decode())
            if binascii.crc32(block) == int(crc, 16):
                chunks.setdefault(int(offset, 16), block)
        ticket = b''.join(chunks.get(offset, b'') for offset in range(0, length, 48))
        if len(ticket) == length and hashlib.sha384(ticket).hexdigest().upper() == digest:
            candidates[f'apticket-{directory[:16]}.der'] = ticket
    return select_ticket(initial_log if initial_log is not None else plain, candidates,
                         ecid, profile, plain if initial_log is not None else None)


def _connection_diagnosis():
    try:
        ids = subprocess.run(['idevice_id', '-l'], capture_output=True, text=True, timeout=12)
        if ids.returncode == 0 and ids.stdout.strip():
            return 'iPhone appears in USB mux, but relay port 2233 did not answer'
        recovery = subprocess.run(['irecovery', '-q'], capture_output=True, text=True, timeout=12)
        mode = re.search(r'(?m)^MODE: (\S+)', recovery.stdout)
        if mode:
            return f'iPhone is still in {mode.group(1)} mode'
    except (OSError, subprocess.TimeoutExpired):
        pass
    return 'iPhone did not appear in USB mux or DFU/Recovery'


def wait_for_setup(say, mode='install', timeout=1200, *, ecid=None, save_snapshot=None):
    if mode not in ('install', 'remove', 'probe'):
        raise ValueError(f'unknown setup mode: {mode}')
    expected_mode = mode.upper().encode()
    completed = b'===== ' + (b'SETUP' if mode == 'install' else b'REMOVE') + b' DONE ====='
    command = ['iproxy', '-s', '127.0.0.1']
    if ecid is not None:
        command.extend(['-u', relay_serial(ecid, mode)])
    command.append(f'{LOCAL_PORT}:{REMOTE_PORT}')
    errors = tempfile.TemporaryFile()
    try:
        proxy = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
    except BaseException:
        errors.close()
        raise
    start = time.monotonic()
    seen = 0
    connected = False
    last_notice = start
    reconnect_suggested = False
    try:
        while time.monotonic() - start < timeout:
            if proxy.poll() is not None:
                errors.seek(0)
                error = errors.read().decode('utf-8', 'replace')[-500:]
                raise SetupError(f'iproxy exited: {error}')
            try:
                initial, transcript = read_snapshot(probe=True) if mode == 'probe' else read_snapshot()
                if save_snapshot is not None:
                    save_snapshot(initial, transcript)
                if not connected:
                    say('USB setup relay connected to the iPhone')
                    connected = True
                if mode == 'probe':
                    if initial is not None or transcript:
                        raise SetupError('USB probe returned unexpected setup data')
                    return initial, transcript
                if len(transcript) < seen:
                    raise SetupError('USB setup relay restarted during setup')
                if len(transcript) > seen:
                    new = transcript[seen:]
                    for line in new.decode('latin1').splitlines():
                        if line.startswith('[rdsetup]') and 'TICKET ' not in line:
                            say(line)
                    seen = len(transcript)
                if b'[usbrelay] rdsetup exited' in transcript or b'[usbrelay] cannot exec rdsetup' in transcript:
                    raise SetupError('rdsetup exited early; its USB transcript is incomplete')
                if b'===== SETUP FAILED' in transcript or b'===== REMOVE FAILED' in transcript:
                    raise SetupError('rdsetup reported failure; inspect the lines above')
                modes = re.findall(rb'===== dualboot setup ramdisk v\d+ \((INSTALL|REMOVE)\) =====', transcript)
                if modes and modes != [expected_mode]:
                    raise SetupError('USB relay is running a different setup operation')
                if completed in transcript:
                    if modes != [expected_mode]:
                        raise SetupError('USB setup completion has no matching operation header')
                    return initial, transcript
                if connected and not transcript and time.monotonic() - start > 90:
                    raise SetupError('USB relay connected but rdsetup did not start')
            except (OSError, socket.timeout) as exc:
                if time.monotonic() - start > 90 and not connected:
                    raise SetupError(f'no USB setup relay after 90 seconds; {_connection_diagnosis()}') from exc
            if time.monotonic() - last_notice >= 30:
                if not connected and not reconnect_suggested:
                    say('USB relay not visible yet. If the iPhone stays black, unplug and reconnect the direct '
                        'Lightning cable once; leave this command running.')
                    reconnect_suggested = True
                else:
                    say(f'waiting for rdsetup over USB ({int(time.monotonic() - start)} seconds elapsed) ...')
                last_notice = time.monotonic()
            time.sleep(2)
        raise SetupError(f'no setup completion over USB after {timeout} seconds')
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.wait()
        errors.close()
