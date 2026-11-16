import io
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'lib'))
import common
import dualboot

REAL_POPEN = subprocess.Popen


class SSHLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.registry = patch.dict(common._SSH_PROXIES, {}, clear=True)
        self.registry.start()
        self.addCleanup(self.registry.stop)
        self.addCleanup(common.close_ssh_proxies)
        self.ws = SimpleNamespace(p=lambda *parts: str(ROOT.joinpath(*parts)))
        self.ssh = common.SSH(self.ws, 'test-phone')
        self.children = []

    def spawn(self, argv, **kwargs):
        process = REAL_POPEN([sys.executable, '-c', 'import time; time.sleep(60)'], **kwargs)
        self.children.append(process)
        self.assertEqual(argv, ['iproxy', '-u', 'test-phone', '-s', '127.0.0.1', '2222:22'])
        return process

    def start_proxy(self):
        with patch.object(common.subprocess, 'run', return_value=SimpleNamespace(returncode=1)), \
                patch.object(common.subprocess, 'Popen', side_effect=self.spawn):
            self.ssh._iproxy()

    def test_owned_forward_is_reused_and_reaped(self):
        self.start_proxy()
        with patch.object(common.subprocess, 'Popen') as spawn:
            common.SSH(self.ws, 'test-phone')._iproxy()
        spawn.assert_not_called()
        process, errors = next(iter(common._SSH_PROXIES.values()))
        common.close_ssh_proxies()
        self.assertIsNotNone(process.poll())
        self.assertTrue(errors.closed)
        self.assertFalse(common._SSH_PROXIES)

    def test_external_forward_is_neither_owned_nor_killed(self):
        with patch.object(common.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run, \
                patch.object(common.subprocess, 'Popen') as spawn:
            self.ssh._iproxy()
            common.close_ssh_proxies()
        spawn.assert_not_called()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][0], 'pgrep')
        self.assertFalse(common._SSH_PROXIES)

    def test_bind_failure_is_reported_without_killing_another_listener(self):
        def rejected(argv, **kwargs):
            process = REAL_POPEN([sys.executable, '-c',
                                 'import sys; print("Address already in use", file=sys.stderr); sys.exit(1)'],
                                **kwargs)
            self.children.append(process)
            return process
        with patch.object(common.subprocess, 'run', return_value=SimpleNamespace(returncode=1)) as run, \
                patch.object(common.subprocess, 'Popen', side_effect=rejected), \
                redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit):
                self.ssh._iproxy()
        self.assertIn('Address already in use', output.getvalue())
        self.assertEqual(run.call_count, 1)
        self.assertFalse(common._SSH_PROXIES)
        self.assertEqual(self.children[0].poll(), 1)

    def test_cli_cleans_up_on_success_error_interrupt_and_signal(self):
        for failure in (None, RuntimeError('failed'), KeyboardInterrupt(), SystemExit(143)):
            with self.subTest(failure=type(failure).__name__):
                def command(args):
                    self.start_proxy()
                    if failure is not None:
                        raise failure
                with patch.object(sys, 'argv', ['dualboot.py']), \
                        patch.object(dualboot, 'cmd_auto', side_effect=command):
                    if failure is None:
                        dualboot.main()
                    else:
                        with self.assertRaises(type(failure)):
                            dualboot.main()
                self.assertIsNotNone(self.children[-1].poll())
                self.assertFalse(common._SSH_PROXIES)

    def test_stubborn_child_is_killed_and_reaped(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('iproxy', 3), 0]
        errors = tempfile.TemporaryFile()
        common._SSH_PROXIES[('test-phone', 2222)] = process, errors
        common.close_ssh_proxies()
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)
        self.assertTrue(errors.closed)

    def test_interactive_ssh_waits_and_preserves_its_exit_status(self):
        state = {'board': 'n104ap', 'build': '24B156', 'installed': True}
        args = SimpleNamespace(ecid='1', remote=[])
        for status, expected in ((0, 0), (255, 255), (-15, 143)):
            with self.subTest(status=status), \
                    patch.object(dualboot, 'irec_query', return_value=None), \
                    patch.object(dualboot, 'workspaces_for', return_value=[('/work/1-24B156', state)]), \
                    patch.object(dualboot, 'find_profile', return_value=state), \
                    patch.object(dualboot, 'Workspace', return_value=SimpleNamespace(ecid='1')), \
                    patch.object(dualboot, 'device_udid', return_value='test-phone'), \
                    patch.object(dualboot, 'SSH') as ssh, \
                    patch.object(dualboot.subprocess, 'run', return_value=SimpleNamespace(returncode=status)) as run, \
                    patch.object(dualboot.os, 'execvp') as replace:
                ssh.return_value._base.return_value = ['-i', '/key']
                with self.assertRaises(SystemExit) as result:
                    dualboot.cmd_ssh(args)
                self.assertEqual(result.exception.code, expected)
                run.assert_called_once_with(['ssh', '-i', '/key', '-p', '2222', 'root@localhost'])
                replace.assert_not_called()

    def test_exit_signal_uses_conventional_status(self):
        with self.assertRaises(SystemExit) as result:
            dualboot.exit_on_signal(signal.SIGHUP, None)
        self.assertEqual(result.exception.code, 129)


if __name__ == '__main__':
    unittest.main()
