import subprocess
import shutil
import sys
import time

import usb.core

from common import board_of, die, irec_query, say


IPHONE_A13_BOARDS = {'n104ap', 'd421ap', 'd431ap', 'd79ap'}
IPHONE_A13_PRODUCTS = {'iPhone12,1', 'iPhone12,3', 'iPhone12,5', 'iPhone12,8'}
RECOVERY_PIDS = (0x1280, 0x1281, 0x1282, 0x1283)


def _usb_present(*products):
    return any(usb.core.find(idVendor=0x05ac, idProduct=pid) is not None for pid in products)


def _dfu_present():
    return _usb_present(0x1227)


class DFUScreen:

    def __init__(self, query):
        self.device = query.get('NAME') or query.get('PRODUCT') or 'iPhone'
        self.mode = query.get('MODE') or '?'
        self.terminal = (sys.stdin.isatty() and sys.stdout.isatty()
                         and shutil.get_terminal_size((80, 24)).columns >= 72)
        self.drawn = False
        self.last_phase = None

    def show(self, phase, remaining=None, detail=''):
        both = 'Press and hold the Side and Volume Down buttons together'
        down = 'Release the Side button BUT KEEP HOLDING Volume Down'
        both += f' ({remaining if phase == "both" and remaining is not None else 4})'
        down += f' ({remaining if phase == "down" and remaining is not None else 10})'
        states = {
            'ready': ('Time to put the device into DFU mode.', 1),
            'both': ('Hold both buttons.', 2),
            'down': ('Keep holding Volume Down.', 3),
            'wait': ('Waiting for the iPhone to appear in DFU mode.', 3),
            'release': ('Release all buttons now.', 0),
            'success': ('Device entered DFU mode successfully.', 0),
            'failure': ("Whoops, the device didn't enter DFU mode.", 0),
            'cancelled': ('Cancelled. Release all buttons.', 0),
        }
        status, active = states[phase]
        if detail:
            status = detail
        if not self.terminal:
            if phase != self.last_phase or remaining is not None or detail:
                count = f' ({remaining})' if remaining is not None else ''
                print(f'[DFU] {status}{count}', flush=True)
            self.last_phase = phase
            return

        def row(content='', highlight=False):
            plain = '║ ' + content[:68].ljust(68) + ' ║'
            return ('\033[1;36m' + plain + '\033[0m') if highlight else plain

        footer = ('[ Cancel: c ]                                      [ Start: Enter ]'
                  if phase == 'ready' else
                  '[ Cancel: c ]                                      [ Retry: Enter ]'
                  if phase == 'failure' else '[ Ctrl-C: cancel ]')
        lines = [
            '╔' + '═' * 70 + '╗',
            row('doublera1n  ·  Enter DFU mode'),
            '╠' + '═' * 70 + '╣',
            row(f'{self.device}  ·  {self.mode} mode'),
            row(),
            row('1. Press Enter to Start', active == 1),
            row('2. ' + both, active == 2),
            row('3. ' + down, active == 3),
            row(),
            row(status),
            row(),
            row(footer),
            '╚' + '═' * 70 + '╝',
        ]
        prefix = '\033[2J\033[H' if not self.drawn else '\033[H'
        sys.stdout.write(prefix + '\n'.join(lines) + '\n\033[J')
        sys.stdout.flush()
        self.drawn = True
        self.last_phase = phase


def _hold(seconds, screen, phase, first=None):
    first = seconds if first is None else first
    for elapsed in range(seconds):
        if _dfu_present():
            return True
        screen.show(phase, first - elapsed)
        time.sleep(1)
    return _dfu_present()


def _verify_dfu(ecid, screen):
    screen.show('release')
    for _ in range(20):
        q = irec_query() if _dfu_present() else None
        if q and q.get('MODE') == 'DFU':
            if q.get('ECID', '').lower() != ecid.lower():
                die('a different device appeared in DFU; stop and check the USB connections')
            screen.show('success')
            return True
        time.sleep(0.25)
    screen.show('failure', detail='DFU USB appeared, but the device identity could not be verified.')
    return False


def _enter_recovery_from_normal():
    devices = subprocess.run(['idevice_id', '-l'], capture_output=True, text=True, timeout=15)
    if devices.returncode:
        die('could not list iPhones over USB; check the direct cable connection')
    udids = [line.strip() for line in devices.stdout.splitlines() if line.strip()]
    if len(udids) != 1:
        die(f'expected exactly one iPhone booted into iOS over USB; found {len(udids)}')
    udid = udids[0]

    def info(key):
        result = subprocess.run(['ideviceinfo', '-u', udid, '-k', key],
                                capture_output=True, text=True, timeout=15)
        if result.returncode or not result.stdout.strip():
            die('could not read the iPhone identity; unlock it and accept Trust on the phone and Mac')
        return result.stdout.strip()

    product = info('ProductType')
    if product not in IPHONE_A13_PRODUCTS:
        die(f'{product} is not an A13 iPhone supported by this guide')
    chip_id = info('UniqueChipID')
    try:
        expected_ecid = int(chip_id, 16 if chip_id.lower().startswith('0x') else 10)
    except ValueError:
        die('could not parse the iPhone ECID from ideviceinfo')

    say(f'{product} detected in normal iOS. Requesting Recovery mode ...')
    entered = subprocess.run(['ideviceenterrecovery', udid],
                             capture_output=True, text=True, timeout=20)
    if entered.returncode:
        detail = (entered.stderr or entered.stdout).strip()[-300:]
        die(f'could not enter Recovery: {detail or "unknown error"}')
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        q = irec_query()
        if q and q.get('MODE') in ('Recovery', 'DFU'):
            if int(q.get('ECID', '0'), 16) != expected_ecid:
                die('the device that appeared in Recovery has a different ECID; stop and check USB')
            return q
        time.sleep(0.25)
    die('Recovery was requested but did not appear over USB within 45 seconds')


def _attempt(ecid, screen):
    if _hold(2, screen, 'both', first=4):
        return _verify_dfu(ecid, screen)

    proc = subprocess.Popen(['irecovery', '-i', ecid, '-n'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    screen.show('both', 2, 'The iPhone is rebooting; keep holding both buttons.')
    deadline = time.monotonic() + 5
    while _usb_present(*RECOVERY_PIDS) and time.monotonic() < deadline:
        if _dfu_present():
            return _verify_dfu(ecid, screen)
        if proc.poll() not in (None, 0):
            die('Recovery reboot command failed; release the buttons and check the cable')
        time.sleep(0.1)
    if _usb_present(*RECOVERY_PIDS):
        die('Recovery did not reboot within 5 seconds; release the buttons')
    if _hold(2, screen, 'both', first=2):
        return _verify_dfu(ecid, screen)

    print('\a', end='', flush=True)
    if _hold(10, screen, 'down'):
        return _verify_dfu(ecid, screen)
    screen.show('wait', detail='Release Volume Down. Checking the USB connection ...')
    if _hold(5, screen, 'wait'):
        return _verify_dfu(ecid, screen)

    q = irec_query()
    mode = q.get('MODE', '?') if q else 'not visible over USB'
    screen.show('failure', detail=f"Whoops, the device didn't enter DFU mode. USB: {mode}.")
    return False


def run_guide():
    while True:
        q = irec_query() or _enter_recovery_from_normal()
        if q.get('MODE') == 'DFU':
            DFUScreen(q).show('success', detail='Device is already in DFU mode.')
            return
        if q.get('MODE') != 'Recovery':
            die(f"expected Recovery, found {q.get('MODE', '?')}")
        if board_of(q) not in IPHONE_A13_BOARDS:
            die('this guide is for A13 iPhones with Side and Volume Down buttons')
        ecid = q.get('ECID') or die('could not read the iPhone ECID in Recovery')
        screen = DFUScreen(q)
        screen.show('ready')
        try:
            choice = input('\n  [ Enter ] Start      [ c ] Cancel: ').strip().lower()
            if choice in ('c', 'cancel', 'q'):
                screen.show('cancelled')
                return
            if choice:
                screen.show('cancelled', detail='Unknown selection. Run the guide again to start.')
                return
            if _attempt(ecid, screen):
                return
            choice = input('\n  [ Enter ] Retry      [ c ] Cancel: ').strip().lower()
            if choice in ('c', 'cancel', 'q'):
                screen.show('cancelled')
                return
        except EOFError:
            die('interactive terminal required for DFU guide')
        except KeyboardInterrupt:
            screen.show('cancelled')
            print()
            raise SystemExit(130)
