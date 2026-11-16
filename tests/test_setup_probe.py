import io
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'lib')]
import dualboot
import mk_setuprd
import setup_usb
from test_setup_ticket import ECID


class ProbeTests(unittest.TestCase):
    def test_probe_image_contains_the_relay_and_omits_an_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = root / 'image/usr/local/bin/restored_external'
            entry.parent.mkdir(parents=True)
            entry.write_bytes(b'original')
            entry.with_name('rdsetup').write_bytes(b'stale installer')
            relay = root / 'relay'
            relay.write_bytes(b'DBPROBE1 ')
            with patch.object(mk_setuprd, 'USBRELAY', str(relay)), \
                    patch.dict(os.environ, {'OSB_SETUP_ECID': ECID}):
                sources = mk_setuprd.stage_payload(str(root / 'image'), 'probe')
            self.assertEqual(sources, (str(relay),))
            self.assertFalse(entry.with_name('rdsetup').exists())
            config = root / 'image/usr/local/share/dualboot'
            self.assertEqual((config / 'mode').read_text(), 'probe\n')
            self.assertEqual((config / 'usb-serial').read_text(), f'doublera1n-probe-{ECID}\n')

    def test_probe_stops_if_the_packaged_relay_lacks_probe_support(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = root / 'usr/local/bin/restored_external'
            entry.parent.mkdir(parents=True)
            entry.write_bytes(b'original')
            legacy = root / 'legacy-relay'
            legacy.write_bytes(b'DBUSB1 ')
            with patch.object(mk_setuprd, 'USBRELAY', str(legacy)):
                with self.assertRaisesRegex(ValueError, 'probe build'):
                    mk_setuprd.stage_payload(directory, 'probe')
            self.assertEqual(entry.read_bytes(), b'original')

    def test_host_probe_selects_the_device_and_operation_before_connecting(self):
        with patch.object(setup_usb.subprocess, 'Popen') as spawn, \
                patch.object(setup_usb, 'read_snapshot', return_value=(None, b'')) as read:
            spawn.return_value.poll.return_value = None
            self.assertEqual(setup_usb.wait_for_setup(lambda _: None, 'probe', ecid=ECID), (None, b''))
            command = spawn.call_args.args[0]
            self.assertEqual(command[command.index('-u') + 1], f'doublera1n-probe-{ECID}')
            read.assert_called_once_with(probe=True)
            spawn.return_value.terminate.assert_called_once()

    def test_probe_rejects_an_install_relay_response(self):
        from test_setup_usb import FakeConnection
        with patch.object(setup_usb.socket, 'create_connection', return_value=FakeConnection(b'DBUSB1 0 0 0\n')):
            with self.assertRaisesRegex(ValueError, 'invalid header'):
                setup_usb.read_snapshot(probe=True)

    def test_probe_command_stays_separate_from_volume_setup(self):
        profile = {'board': 'd421ap', 'build': '24A5380h', 'version': '27.0'}
        args = SimpleNamespace(build=profile['build'], ipsw='beta.ipsw')
        ws = SimpleNamespace()
        with ExitStack() as stack:
            values = {'host_check': [], 'wait_dfu': {'ECID': ECID}, 'board_of': 'd421ap',
                      'load_selected': {}, 'ensure_profile': profile, 'Workspace': ws, 'find_ipsw': 'beta.ipsw'}
            for name, value in values.items():
                stack.enter_context(patch.object(dualboot, name, return_value=value))
            methods = {name: stack.enter_context(patch.object(dualboot, name)) for name in
                       ('extract_ipsw', 'prepare_tickets', 'build_setup_chain', 'setup_boot',
                        'prepare_rootfs', 'complete_profile', 'cmd_install', 'cmd_provision')}
            stack.enter_context(redirect_stdout(io.StringIO()))
            dualboot.cmd_probe(args)
            dualboot.Workspace.assert_called_once_with(ECID, profile, prefix='probe-')
            methods['build_setup_chain'].assert_called_once_with(ws, 'probe')
            methods['setup_boot'].assert_called_once_with(ws, 'probe')
            for name in ('prepare_rootfs', 'complete_profile', 'cmd_install', 'cmd_provision'):
                methods[name].assert_not_called()


@unittest.skipUnless(shutil.which('cc'), 'requires a C compiler for the relay fixture')
class ProbeRelayTests(unittest.TestCase):
    def test_live_probe_replies_twice_without_executing_its_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'CoreFoundation').mkdir()
            (root / 'IOKit').mkdir()
            (root / 'CoreFoundation/CoreFoundation.h').write_text('''
#include <stddef.h>
typedef const void *CFTypeRef;
typedef const void *CFStringRef;
typedef const void *CFAllocatorRef;
#define CFSTR(x) ((CFStringRef)(x))
#define kCFAllocatorDefault NULL
#define kCFStringEncodingASCII 0
void CFRelease(CFTypeRef);
CFStringRef CFStringCreateWithCString(CFAllocatorRef, const char *, int);
''')
            (root / 'IOKit/IOKitLib.h').write_text('''
typedef int IOReturn;
typedef int io_service_t;
#define kIOReturnError 1
#define kIOReturnSuccess 0
void *IOServiceMatching(const char *);
io_service_t IOServiceGetMatchingService(int, void *);
void IOObjectRelease(io_service_t);
''')
            stub = root / 'usb-fixture.c'
            stub.write_text('''
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
void CFRelease(CFTypeRef value) { (void)value; }
CFStringRef CFStringCreateWithCString(CFAllocatorRef a, const char *s, int e) {
    (void)a; (void)e; return (CFStringRef)strdup(s);
}
CFTypeRef IOUSBDeviceDescriptionCreateWithType(CFAllocatorRef a, CFStringRef s) {
    (void)a; if (strcmp((const char *)s, "standardMuxOnly")) abort(); return (CFTypeRef)1;
}
void IOUSBDeviceDescriptionSetSerialString(CFTypeRef d, CFStringRef s) {
    (void)d; if (strcmp((const char *)s, getenv("EXPECTED_USB_SERIAL"))) abort();
}
IOReturn IOUSBDeviceControllerCreate(CFAllocatorRef a, CFTypeRef *c) {
    (void)a; *c = (CFTypeRef)1; return 0;
}
IOReturn IOUSBDeviceControllerSetDescription(CFTypeRef c, CFTypeRef d) {
    (void)c; (void)d; return 0;
}
void *IOServiceMatching(const char *s) { (void)s; return (void *)1; }
io_service_t IOServiceGetMatchingService(int p, void *m) { (void)p; (void)m; return 1; }
void IOObjectRelease(io_service_t s) { (void)s; }
''')
            mode, serial = root / 'mode', root / 'serial'
            mode.write_text('probe\n')
            identity = setup_usb.relay_serial(ECID, 'probe')
            serial.write_text(identity + '\n')
            marker = root / 'installer-ran'
            child = root / 'installer'
            child.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
            child.chmod(0o755)
            with socket.socket() as available:
                available.bind(('127.0.0.1', 0))
                port = available.getsockname()[1]
            binary = root / 'relay'
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-I', str(root),
                            f'-DRELAY_PORT={port}', f'-DMODE_PATH="{mode}"', f'-DSERIAL_PATH="{serial}"',
                            f'-DRDSETUP_PATH="{child}"', str(ROOT / 'src/rdsetup_usbrelay.c'), str(stub),
                            '-o', str(binary)], check=True, capture_output=True)
            process = subprocess.Popen([str(binary)], env=dict(os.environ, EXPECTED_USB_SERIAL=identity))
            try:
                deadline = time.monotonic() + 3
                while True:
                    try:
                        reply = setup_usb.read_snapshot(port, probe=True)
                        break
                    except OSError:
                        if time.monotonic() > deadline or process.poll() is not None:
                            self.fail('probe relay did not start')
                        time.sleep(0.02)
                self.assertEqual(reply, (None, b''))
                self.assertEqual(setup_usb.read_snapshot(port, probe=True), (None, b''))
                self.assertFalse(marker.exists())
                self.assertIsNone(process.poll())
            finally:
                process.terminate()
                process.wait(timeout=3)


if __name__ == '__main__':
    unittest.main()
