import os
import re
import subprocess
import time

import usb.core
import usb.util


def _present(pid):
    device = usb.core.find(idVendor=0x05ac, idProduct=pid)
    if device is None:
        return False
    usb.util.dispose_resources(device)
    return True


def _stop_helper(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError('could not stop the iBSS helper; do not start another boot command') from exc


def _verify_recovery(ecid, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        device = usb.core.find(idVendor=0x05ac, idProduct=0x1281)
        if device is not None:
            try:
                device.default_timeout = 500
                serial = device.serial_number or ''
                chip = re.search(r'\bCPID:([0-9a-f]+)\b', serial, re.I)
                ident = re.search(r'\bECID:([0-9a-f]+)\b', serial, re.I)
                if chip and ident:
                    if int(chip[1], 16) != 0x8030 or int(ident[1], 16) != ecid:
                        raise RuntimeError('a different device appeared in Recovery; stopping before iBEC')
                    return
            except (usb.core.USBError, ValueError):
                pass
            finally:
                usb.util.dispose_resources(device)
        time.sleep(0.25)
    raise RuntimeError('Recovery appeared, but its identity did not respond; stopping before iBEC')


def boot_ibss(command, ecid, log_path, timeout=60):
    expected_ecid = int(ecid, 16)
    if _present(0x1281):
        raise RuntimeError('another Recovery device is already connected; connect only the target iPhone')
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    print(f'   iBSS helper log: {log_path}', flush=True)
    found = False
    with open(log_path, 'wb') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        started = time.monotonic()
        deadline = started + timeout
        notice = started + 10
        try:
            while time.monotonic() < deadline:
                if _present(0x1281):
                    found = True
                    break
                now = time.monotonic()
                if now >= notice:
                    state = ('helper running' if process.poll() is None
                             else f'helper exited {process.returncode}')
                    print(f'   waiting for iBSS Recovery ({int(now - started)}s; {state})', flush=True)
                    notice = now + 10
                time.sleep(max(0, min(0.25, deadline - now)))
        finally:
            _stop_helper(process)
    if not found:
        with open(log_path, 'rb') as log:
            log.seek(max(0, os.fstat(log.fileno()).st_size - 800))
            detail = log.read().decode('utf-8', 'replace').replace('\r', '\n').strip()
        state = 'phone still in DFU' if _present(0x1227) else 'phone absent from DFU/Recovery'
        raise RuntimeError(f'no iBSS Recovery after {timeout:g}s ({state}); helper exit {process.returncode}.\n'
                           f'   Log: {log_path}\n{detail}')
    _verify_recovery(expected_ecid)
    print('   iBSS Recovery is responding; helper closed', flush=True)
