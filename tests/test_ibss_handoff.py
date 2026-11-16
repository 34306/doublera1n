import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import ibss_handoff


ECID = '0x000160940aa3802e'
REAL_POPEN = subprocess.Popen


class IbssHandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = str(Path(self.tmp.name) / 'ibss.log')
        self.children = []
        self.addCleanup(self.stop_children)

    def stop_children(self):
        for process in self.children:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)

    def spawn(self, *args, **kwargs):
        process = REAL_POPEN(*args, **kwargs)
        self.children.append(process)
        return process

    def run_handoff(self, script, present, verify=None, timeout=1):
        with patch.object(ibss_handoff, '_present', side_effect=present), \
                patch.object(ibss_handoff, '_verify_recovery', side_effect=verify) as check, \
                patch.object(ibss_handoff.subprocess, 'Popen', side_effect=self.spawn), \
                redirect_stdout(io.StringIO()):
            ibss_handoff.boot_ibss([sys.executable, '-u', '-c', script], ECID, self.log, timeout)
        return check

    def test_recovery_releases_blocked_helper_before_querying_new_interface(self):
        def present(pid):
            return pid == 0x1281 and bool(self.children)

        def verify(ecid):
            self.assertEqual(ecid, int(ECID, 16))
            self.assertIsNotNone(self.children[0].poll())

        check = self.run_handoff('import time; time.sleep(60)', present, verify)
        check.assert_called_once_with(int(ECID, 16))
        self.assertLess(self.children[0].returncode, 0)

    def test_recovery_accepts_nonzero_helper_exit_after_usb_disconnect(self):
        def present(pid):
            return pid == 0x1281 and bool(self.children) and self.children[0].poll() is not None

        check = self.run_handoff('import sys; print("USB disconnected"); sys.exit(7)', present)
        check.assert_called_once()
        self.assertEqual(self.children[0].returncode, 7)

    def test_successful_process_exit_without_recovery_is_not_boot_success(self):
        with self.assertRaisesRegex(RuntimeError, 'no iBSS Recovery'):
            self.run_handoff('pass', lambda pid: False, timeout=0.2)

    def test_no_handoff_times_out_and_reaps_helper(self):
        with self.assertRaisesRegex(RuntimeError, 'phone still in DFU'):
            self.run_handoff('import time; time.sleep(60)', lambda pid: pid == 0x1227, timeout=0.1)
        self.assertIsNotNone(self.children[0].poll())

    def test_interrupt_reaps_helper(self):
        def present(pid):
            if self.children:
                raise KeyboardInterrupt
            return False

        with self.assertRaises(KeyboardInterrupt):
            self.run_handoff('import time; time.sleep(60)', present)
        self.assertIsNotNone(self.children[0].poll())

    def test_wrong_device_is_rejected_before_ibec(self):
        device = Mock(serial_number='CPID:8030 ECID:0000000000000001')
        with patch.object(ibss_handoff.usb.core, 'find', return_value=device), \
                patch.object(ibss_handoff.usb.util, 'dispose_resources') as release:
            with self.assertRaisesRegex(RuntimeError, 'different device'):
                ibss_handoff._verify_recovery(int(ECID, 16))
            release.assert_called_once_with(device)


if __name__ == '__main__':
    unittest.main()
