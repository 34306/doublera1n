import argparse
import io
import plistlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'lib'))
import dualboot
import mk_setuprd
import setup_usb
from test_setup_ticket import ECID, PROFILE, fixture
from test_setup_usb import transcript_for


class CliTests(unittest.TestCase):
    def test_cli_exposes_the_dfu_guide_and_relay_probe(self):
        parse_args = argparse.ArgumentParser.parse_args
        parsers = []

        def observe(parser, *args, **kwargs):
            parsers.append(parser)
            return parse_args(parser, *args, **kwargs)

        with patch.object(argparse.ArgumentParser, 'parse_args', observe), \
                patch.object(sys, 'argv', ['dualboot.py']), patch.object(dualboot, 'cmd_auto') as auto:
            dualboot.main()
        auto.assert_called_once()
        parser = parsers[0]
        options = {option for action in parser._actions for option in action.option_strings}
        self.assertEqual(options, {'-h', '--help', '--no-wait', '--dfu-guide'})
        sub = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
        self.assertEqual(set(sub.choices), {'boot', 'install', 'probe', 'remove', 'provision', 'status', 'doctor',
                                          'ssh', 'rebuild', 'versions', 'select', 'precheck', 'profile', 'os2'})
        self.assertNotIn('--usb-setup', sub.choices['install']._option_string_actions)

    def test_dfu_flag_runs_only_the_guide(self):
        with patch.object(sys, 'argv', ['dualboot.py', '--dfu-guide']), \
                patch.object(dualboot, 'cmd_dfu_guide') as guide, patch.object(dualboot, 'cmd_auto') as auto:
            dualboot.main()
        guide.assert_called_once()
        auto.assert_not_called()

    def test_removed_commands_and_conflicting_guide_are_rejected(self):
        for args in (['dfu-guide'], ['usb-probe'], ['recover-setup'], ['migrate-workspace'],
                     ['install', '--usb-setup'], ['--dfu-guide', 'install']):
            with self.subTest(args=args), patch.object(sys, 'argv', ['dualboot.py', *args]), \
                    patch.object(dualboot, 'cmd_install') as install, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    dualboot.main()
                self.assertEqual(result.exception.code, 2)
                install.assert_not_called()


class SetupDefaultsTests(unittest.TestCase):
    def test_install_and_remove_package_the_usb_relay_by_default(self):
        for mode in ('install', 'remove'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                entry = root / 'usr/local/bin/restored_external'
                entry.parent.mkdir(parents=True)
                entry.write_bytes(b'original restore service')
                inputs = mk_setuprd.stage_payload(directory, mode)
                self.assertEqual(entry.read_bytes(), Path(mk_setuprd.USBRELAY).read_bytes())
                child = entry.with_name('rdsetup')
                self.assertEqual(child.read_bytes(), Path(mk_setuprd.RDSETUP).read_bytes())
                self.assertEqual(child.stat().st_mode & 0o777, 0o755)
                self.assertEqual(inputs, (mk_setuprd.RDSETUP, mk_setuprd.USBRELAY))
                self.assertEqual((root / 'usr/local/share/dualboot/mode').read_text(), mode + '\n')

    def test_missing_relay_stops_before_replacing_restore_service(self):
        with tempfile.TemporaryDirectory() as directory:
            entry = Path(directory) / 'usr/local/bin/restored_external'
            entry.parent.mkdir(parents=True)
            entry.write_bytes(b'original')
            with patch.object(mk_setuprd, 'USBRELAY', '/missing-relay'):
                with self.assertRaisesRegex(ValueError, 'relay missing'):
                    mk_setuprd.stage_payload(directory, 'install')
            self.assertEqual(entry.read_bytes(), b'original')

    def test_setup_boot_uses_usb_without_transport_flags(self):
        for mode in ('install', 'remove'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                ws = SimpleNamespace(p=lambda *parts: str(Path(directory).joinpath(*parts)), env=lambda: {}, ecid=ECID)
                (Path(directory) / 'logs').mkdir()
                with patch.object(dualboot, 'run', return_value=SimpleNamespace(returncode=0)) as run, \
                        patch.object(setup_usb, 'wait_for_setup', return_value=(None, b'real log')) as wait, \
                        redirect_stdout(io.StringIO()):
                    self.assertEqual(dualboot.setup_boot(ws, mode), (None, b'real log'))
                wait.assert_called_once()
                self.assertEqual(wait.call_args.kwargs['mode'], mode)
                self.assertEqual(wait.call_args.kwargs['ecid'], ECID)
                self.assertTrue(callable(wait.call_args.kwargs['save_snapshot']))
                self.assertEqual(run.call_args.args, (sys.executable, str(ROOT / 'lib/boot_chain.py')))
                saved = next((Path(directory) / 'logs').glob(f'setup-{mode}-*.log'))
                self.assertEqual(saved.read_bytes(), b'real log')
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    def test_setup_chain_failure_never_starts_usb_result_reader(self):
        with patch.object(dualboot, 'run', return_value=SimpleNamespace(returncode=1)), \
                patch.object(setup_usb, 'wait_for_setup') as wait, redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                dualboot.setup_boot(SimpleNamespace(env=lambda: {}), 'install')
        wait.assert_not_called()

    def test_install_without_extra_flags_verifies_ticket_and_provisions(self):
        log, files = fixture()
        ticket = next(iter(files.values()))
        profile = dict(PROFILE, board='n104ap', version='27.2.1', tested=True)
        q = {'ECID': ECID, 'MODE': 'DFU', 'PWND': 'usbliter8'}
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            (root / 'out').mkdir()
            ws = SimpleNamespace(ecid=ECID, profile=profile, state={}, save=Mock(),
                                 p=lambda *parts: str(root.joinpath(*parts)))
            values = {'host_check': [], 'load_selected': dict(profile), 'wait_dfu': q,
                      'board_of': 'n104ap', 'ensure_profile': profile, 'Workspace': ws,
                      'installed_ws': None, 'find_ipsw': 'fixture.ipsw',
                      'setup_boot': (None, transcript_for(log, ticket)), 'device_udid': 'test-device'}
            mocks = {name: stack.enter_context(patch.object(dualboot, name, return_value=value))
                     for name, value in values.items()}
            for name in ('extract_ipsw', 'prepare_rootfs', 'complete_profile', 'prepare_tickets',
                         'prepare_iboot', 'build_setup_chain', 'ensure_daemons', 'build_osb',
                         'cmd_boot', 'cmd_provision', 'say', 'warn'):
                mocks[name] = stack.enter_context(patch.object(dualboot, name))
            ssh = stack.enter_context(patch.object(dualboot, 'SSH'))
            ssh.return_value.wait.return_value = True
            args = SimpleNamespace(build=None, ipsw=None, skip_precheck=True)
            dualboot.cmd_install(args)
            mocks['build_setup_chain'].assert_called_once_with(ws, 'install')
            mocks['setup_boot'].assert_called_once_with(ws, 'install')
            self.assertTrue(ws.state['installed'])
            self.assertEqual((root / 'out/apticket.installed.der').read_bytes(), ticket)
            mocks['cmd_boot'].assert_called_once_with(args)
            mocks['cmd_provision'].assert_called_once_with(args)


class RelayCompletionTests(unittest.TestCase):
    def check_result(self, mode, transcript, error=None):
        with patch.object(setup_usb.subprocess, 'Popen') as spawn, \
                patch.object(setup_usb, 'read_snapshot', return_value=(None, transcript)):
            spawn.return_value.poll.return_value = None
            if error:
                with self.assertRaisesRegex(ValueError, error):
                    setup_usb.wait_for_setup(lambda _: None, mode)
            else:
                self.assertEqual(setup_usb.wait_for_setup(lambda _: None, mode), (None, transcript))
            self.assertIn('23330:2233', spawn.call_args.args[0])
            spawn.return_value.terminate.assert_called_once()
            spawn.return_value.wait.assert_called_once()

    def test_install_completion(self):
        self.check_result('install', b'[rdsetup] ===== dualboot setup ramdisk v3 (INSTALL) =====\n'
                          b'[rdsetup] ===== SETUP DONE =====\n')

    def test_remove_completion(self):
        self.check_result('remove', b'[rdsetup] ===== dualboot setup ramdisk v3 (REMOVE) =====\n'
                          b'[rdsetup] ===== REMOVE DONE =====\n')

    def test_remove_failure_is_not_success(self):
        self.check_result('remove', b'[rdsetup] ===== REMOVE FAILED =====\n', 'reported failure')

    def test_another_operation_is_rejected(self):
        self.check_result('remove', b'[rdsetup] ===== dualboot setup ramdisk v3 (INSTALL) =====\n'
                          b'[rdsetup] ===== SETUP DONE =====\n', 'different setup operation')

    def test_completion_without_operation_header_is_rejected(self):
        self.check_result('install', b'[rdsetup] ===== SETUP DONE =====\n', 'no matching operation')

    def test_update_accepts_original_copy_log_and_verifies_current_build(self):
        prior, _ = fixture(build='24B119')
        current, files = fixture()
        current = current.replace(b'  copyfile -> 0 (ok), files=42, skipped dirs=0\n',
                                  b'DataB already set up - template copy skipped\n')
        ticket = next(iter(files.values()))
        _, received = setup_usb.ticket_from_transcript(prior, transcript_for(current, ticket), ECID, PROFILE)
        self.assertEqual(received, ticket)
        with self.assertRaisesRegex(ValueError, 'build'):
            setup_usb.ticket_from_transcript(prior, transcript_for(current, ticket), ECID,
                                             dict(PROFILE, build='another-build'))


@unittest.skipUnless(sys.platform == 'darwin', 'requires macOS binary tools')
class RelayBinaryTests(unittest.TestCase):
    def test_signed_relay_links_usb_framework_and_exports_installer_protocol(self):
        binary = ROOT / 'payload/setup/rdsetup_usbrelay'
        libraries = subprocess.check_output(['otool', '-L', str(binary)], text=True)
        self.assertIn('/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit', libraries)
        self.assertIn('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation', libraries)
        symbols = subprocess.check_output(['nm', '-u', str(binary)], text=True).splitlines()
        for name in ('_IOUSBDeviceControllerSetDescription', '_IOUSBDeviceDescriptionCreateWithType', '_execl'):
            self.assertIn(name, symbols)
        self.assertNotIn('_dlopen', symbols)
        self.assertNotIn('_dlsym', symbols)
        entitlements = plistlib.loads(subprocess.check_output(['ldid', '-e', str(binary)]))
        self.assertTrue(entitlements['com.apple.private.usbdevice.setdescription'])
        self.assertTrue(entitlements['platform-application'])
        self.assertIn(b'DBUSB1 ', binary.read_bytes())
        self.assertIn(b'DBPROBE1 ', binary.read_bytes(), 'Run bash src/build_usbrelay.sh before the Mac checks')


if __name__ == '__main__':
    unittest.main()
