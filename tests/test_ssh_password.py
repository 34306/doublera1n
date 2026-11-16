import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAKE_TOOL = r'''
import json
import os
from pathlib import Path
import sys

root = Path(os.environ['SSH_TEST_DIR'])
statefile = root / 'state.json'
state = json.loads(statefile.read_text())
tool = Path(sys.argv[0]).name
args = sys.argv[1:]
state['calls'].append([tool, *args])
code = 0
if tool == 'id':
    print(state.get('uid', 0))
elif tool == 'pw':
    assert args == ['usermod', 'root', '-h', '0']
    assert sys.stdin.read() == 'alpine\n'
    code = state.get('pw_error', 0)
    if not code:
        database = root / 'etc/master.passwd'
        lines = database.read_text().splitlines()
        for i, line in enumerate(lines):
            if line.startswith('root:'):
                fields = line.split(':')
                fields[1] = '$6$fixture-password'
                lines[i] = ':'.join(fields)
        database.write_text('\n'.join(lines) + '\n')
elif tool == 'sshd':
    if '-T' in args:
        print(state.get('effective', 'permitrootlogin yes\npasswordauthentication yes'))
    else:
        state['alive']['303'] = True
        (root / 'var/run/sshd.pid').write_text('303\n')
elif tool == 'mkdir':
    assert args[0] == '-p'
    for path in args[1:]:
        Path(path).mkdir(parents=True, exist_ok=True)
elif tool == 'sleep':
    pass
elif tool == 'kill-stub':
    pid = args[-1]
    if args[0] == '-0':
        code = 0 if state['alive'].get(pid, False) else 1
    else:
        assert args[0] == '-TERM'
        state['alive'][pid] = False
else:
    raise AssertionError(tool)
statefile.write_text(json.dumps(state))
sys.exit(code)
'''

PROCESS_FIXTURE = r'''
#include <stddef.h>
#include <sys/proc_info.h>
#define getuid fixture_getuid
#define proc_pidinfo fixture_pidinfo
#define proc_pidpath fixture_pidpath
#define csops fixture_csops
#include "ssh-listener.c"

_Static_assert(sizeof(struct process_info) == sizeof(struct proc_bsdshortinfo), "size");
_Static_assert(offsetof(struct process_info, ppid) == offsetof(struct proc_bsdshortinfo, pbsi_ppid), "parent");
_Static_assert(offsetof(struct process_info, uid) == offsetof(struct proc_bsdshortinfo, pbsi_uid), "uid");

uid_t fixture_getuid(void) { return (uid_t)atoi(getenv("SSH_TEST_UID")); }

int fixture_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int size) {
    if (flavor != 13 || arg || size != sizeof(struct process_info)) return 0;
    if (getenv("SSH_TEST_INFO_ERROR") || (pid != 101 && pid != 202)) return 0;
    struct process_info *info = buffer;
    info->pid = (uint32_t)pid;
    info->ppid = pid == 101 ? (uint32_t)atoi(getenv("SSH_TEST_PARENT")) : 1;
    info->uid = getenv("SSH_TEST_PROCESS_UID") ? (uint32_t)atoi(getenv("SSH_TEST_PROCESS_UID")) : 0;
    const char *name = getenv("SSH_TEST_PROCESS_NAME");
    snprintf(info->name, sizeof(info->name), "%s", name ? name : pid == 101 ? "sshd" : "jbloader");
    return sizeof(*info);
}

int fixture_pidpath(int pid, void *buffer, uint32_t size) {
    if (getenv("SSH_TEST_PATH_ERROR")) { errno = EPERM; return 0; }
    const char *missing = getenv("SSH_TEST_PATH_MISSING");
    if (missing && (!strcmp(missing, "all") || atoi(missing) == pid)) { errno = ENOENT; return 0; }
    const char *path = getenv(pid == 101 ? "SSH_TEST_LISTENER" : "SSH_TEST_SUPERVISOR");
    return snprintf(buffer, size, "%s", path);
}

int fixture_csops(pid_t pid, unsigned int operation, void *buffer, size_t size) {
    if (getenv("SSH_TEST_IDENTITY_ERROR")) { errno = EACCES; return -1; }
    if (operation != 11 || size < 8) return -1;
    const char *identity = getenv("SSH_TEST_CODE_IDENTITY");
    if (!identity || !identity[0]) identity = pid == 101 ? "sshd" : "jbloader";
    size_t length = strlen(identity) + 1;
    if (size < 8 + length) return -1;
    uint32_t *header = buffer;
    header[0] = 0;
    header[1] = htonl((uint32_t)(8 + length));
    if (getenv("SSH_TEST_IDENTITY_LENGTH")) header[1] = htonl(512);
    memcpy((char *)buffer + 8, identity, length);
    return 0;
}
'''


class SSHPasswordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='ssh listener ')
        cls.addClassCleanup(cls.build.cleanup)
        harness = Path(cls.build.name) / 'process-fixture.c'
        harness.write_text(PROCESS_FIXTURE)
        cls.inspector = Path(cls.build.name) / 'ssh-listener'
        subprocess.run(['xcrun', 'clang', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-I', str(ROOT / 'src/jbinit'), str(harness), '-o', str(cls.inspector)],
                       check=True, capture_output=True, text=True, timeout=30)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ssh password ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for directory in ('etc', 'usr/bin', 'usr/sbin', 'var/run', 'var/log'):
            self.root.joinpath(directory).mkdir(parents=True)
        self.database = self.root / 'etc/master.passwd'
        self.database.write_text('root:!:0:0::0:0:root:/var/root:/bin/sh\nmobile:*:501:501::0:0:mobile:/var/mobile:/bin/sh\n')
        self.marker = self.root / '.root-password-initialized'
        self.statefile = self.root / 'state.json'
        self.statefile.write_text(json.dumps({'calls': [], 'alive': {'101': True, '202': True, '404': True}}))
        (self.root / 'var/run/sshd.pid').write_text('101\n')
        for name in ('id', 'pw', 'sshd', 'kill-stub', 'sleep', 'mkdir'):
            directory = 'usr/sbin' if name in ('pw', 'sshd') else 'usr/bin'
            path = self.root / directory / name
            path.write_text(f'#!{sys.executable}\n' + FAKE_TOOL)
            path.chmod(0o755)
        shutil.copy2(self.inspector, self.root / 'usr/bin/ssh-listener')
        script = (ROOT / 'device/ssh-setup.sh').read_text()
        script = script.replace('JB=/var/jb\n', 'JB=' + shlex.quote(str(self.root)) + '\n'
                                'kill() { "$JB/usr/bin/kill-stub" "$@"; }\n', 1)
        self.assertIn(':$JB/sbin:/usr/bin:/bin:/usr/sbin:/sbin"', script)
        script = script.replace(':$JB/sbin:/usr/bin:/bin:/usr/sbin:/sbin"', ':$JB/sbin"', 1)
        self.script = self.root / 'ssh-setup.sh'
        self.script.write_text(script)

    def state(self, **changes):
        data = json.loads(self.statefile.read_text())
        if changes:
            data.update(changes)
            self.statefile.write_text(json.dumps(data))
        return data

    def run_setup(self, mode='init'):
        state = self.state()
        return subprocess.run(['/bin/sh', str(self.script), mode],
                              env=dict(os.environ, SSH_TEST_DIR=str(self.root), SSH_TEST_UID=str(state.get('uid', 0)),
                                       SSH_TEST_PARENT=str(state.get('parent', 202)),
                                       SSH_TEST_LISTENER=state.get('listener_name', '/var/jb/usr/sbin/sshd'),
                                       SSH_TEST_SUPERVISOR=state.get('parent_name', '/jbin/jbloader'),
                                       SSH_TEST_PATH_MISSING=state.get('missing_path', ''),
                                       SSH_TEST_CODE_IDENTITY=state.get('code_identity', '')),
                              capture_output=True, text=True, timeout=10)

    def test_locked_root_is_initialized_once(self):
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        self.assertIn('root:$6$fixture-password:', self.database.read_text())
        self.database.write_text(self.database.read_text().replace('$6$fixture-password', '!'))
        self.assertEqual(self.run_setup().returncode, 0)
        self.assertEqual(sum(call[0] == 'pw' for call in self.state()['calls']), 1)
        self.assertIn('root:!:', self.database.read_text())

    def test_existing_password_is_preserved(self):
        self.database.write_text(self.database.read_text().replace('root:!:', 'root:$6$chosen:'))
        self.assertEqual(self.run_setup().returncode, 0)
        self.assertIn('root:$6$chosen:', self.database.read_text())
        self.assertFalse(any(call[0] == 'pw' for call in self.state()['calls']))

    def test_password_failure_does_not_mark_initialization_complete(self):
        self.state(pw_error=1)
        self.assertNotEqual(self.run_setup().returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertIn('root:!:', self.database.read_text())

    def test_nonroot_cannot_change_the_database(self):
        self.state(uid=501)
        self.assertNotEqual(self.run_setup().returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(any(call[0] == 'pw' for call in self.state()['calls']))

    def test_live_restart_only_stops_the_listener_and_its_known_supervisor(self):
        for name in ('/var/jb/usr/sbin/sshd', '/private/var/jb/usr/sbin/sshd'):
            with self.subTest(name=name):
                self.state(calls=[], alive={'101': True, '202': True, '404': True}, listener_name=name)
                (self.root / 'var/run/sshd.pid').write_text('101\n')
                result = self.run_setup('restart')
                self.assertEqual(result.returncode, 0, result.stderr)
                state = self.state()
                killed = [call for call in state['calls'] if call[:2] == ['kill-stub', '-TERM']]
                self.assertEqual(killed, [['kill-stub', '-TERM', '202'], ['kill-stub', '-TERM', '101']])
                self.assertTrue(state['alive']['404'])
                self.assertTrue(state['alive']['303'])
                self.assertIn('password login enabled', result.stdout)
                self.assertLess(next(i for i, call in enumerate(state['calls']) if call[:2] == ['sshd', '-T']),
                                next(i for i, call in enumerate(state['calls']) if call[:2] == ['kill-stub', '-TERM']))

    def test_daemonized_listener_does_not_signal_launchd(self):
        self.state(parent=1)
        result = self.run_setup('restart')
        self.assertEqual(result.returncode, 0, result.stderr)
        killed = [call for call in self.state()['calls'] if call[:2] == ['kill-stub', '-TERM']]
        self.assertEqual(killed, [['kill-stub', '-TERM', '101']])

    def test_live_restart_checks_code_identity_when_process_path_is_unresolvable(self):
        for missing in ('101', '202', 'all'):
            with self.subTest(missing=missing):
                self.state(calls=[], alive={'101': True, '202': True, '404': True}, missing_path=missing)
                (self.root / 'var/run/sshd.pid').write_text('101\n')
                result = self.run_setup('restart')
                self.assertEqual(result.returncode, 0, result.stderr)
                state = self.state()
                killed = [call for call in state['calls'] if call[:2] == ['kill-stub', '-TERM']]
                self.assertEqual(killed, [['kill-stub', '-TERM', '202'], ['kill-stub', '-TERM', '101']])
                self.assertTrue(state['alive']['404'])

    def test_wrong_code_identity_with_unresolvable_path_stops_before_any_signal(self):
        self.state(missing_path='all', code_identity='unrelated')
        result = self.run_setup('restart')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('expected sshd code identity', result.stderr)
        self.assertFalse(any(call[0] == 'kill-stub' for call in self.state()['calls']))

    def test_missing_inspector_stops_before_any_signal(self):
        (self.root / 'usr/bin/ssh-listener').unlink()
        result = self.run_setup('restart')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Copy payload/boot/ssh-listener', result.stderr)
        self.assertFalse(any(call[0] == 'kill-stub' for call in self.state()['calls']))

    def test_missing_or_invalid_root_entry_does_not_initialize_password(self):
        for database in ('mobile:*:501:501::0:0:mobile:/var/mobile:/bin/sh\n',
                         'root:!\n', 'root:!:501:501::0:0:root:/var/root:/bin/sh\n'):
            with self.subTest(database=database):
                self.database.write_text(database)
                self.state(calls=[])
                self.assertNotEqual(self.run_setup().returncode, 0)
                self.assertFalse(self.marker.exists())
                self.assertFalse(any(call[0] == 'pw' for call in self.state()['calls']))

    def test_initialization_does_not_need_the_process_inspector(self):
        (self.root / 'usr/bin/ssh-listener').unlink()
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())

    def test_unexpected_process_or_disabled_password_login_stops_before_any_signal(self):
        for values in ({'listener_name': '/usr/sbin/unrelated'}, {'parent_name': '/sbin/launchd'},
                       {'effective': 'permitrootlogin prohibit-password\npasswordauthentication no'},
                       {'effective': 'permitrootlogin yes'}, {'effective': 'passwordauthentication yes'},
                       {'parent': 0}, {'parent': 101}):
            with self.subTest(values=values):
                self.state(calls=[], listener_name='/var/jb/usr/sbin/sshd', parent_name='/jbin/jbloader',
                           effective='permitrootlogin yes\npasswordauthentication yes', parent=202)
                self.state(**values)
                result = self.run_setup('restart')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call[0] == 'kill-stub' for call in self.state()['calls']))

    def test_bundled_bootstrap_supplies_external_commands_and_root_login_config(self):
        with tarfile.open(ROOT / 'payload/boot/bootstrap.tar.gz') as bundle:
            entries = {entry.name.lstrip('./'): entry for entry in bundle}
            for command in ('usr/sbin/pw', 'usr/sbin/sshd', 'usr/bin/id', 'usr/bin/mkdir',
                            'usr/bin/sleep', 'usr/bin/dash'):
                self.assertIn('var/jb/' + command, entries)
            config = bundle.extractfile(entries['var/jb/etc/ssh/sshd_config']).read().decode()
        self.assertIn('\nPermitRootLogin yes\n', config)
        self.assertNotIn('\nPasswordAuthentication no\n', config)

    def test_process_inspector_rejects_invalid_identity_or_missing_information(self):
        environment = dict(os.environ, SSH_TEST_UID='0', SSH_TEST_PARENT='202',
                           SSH_TEST_LISTENER='/var/jb/usr/sbin/sshd', SSH_TEST_SUPERVISOR='/jbin/jbloader')
        for argument, changes in (('1', {}), ('-1', {}), ('0', {}), ('101x', {}),
                                  ('999999999999999999999', {}), ('404', {}),
                                  ('101', {'SSH_TEST_UID': '501'}),
                                  ('101', {'SSH_TEST_PROCESS_UID': '501'}),
                                  ('101', {'SSH_TEST_INFO_ERROR': '1'}),
                                  ('101', {'SSH_TEST_PATH_ERROR': '1'}),
                                  ('101', {'SSH_TEST_PATH_MISSING': 'all', 'SSH_TEST_PROCESS_NAME': 'unrelated'}),
                                  ('101', {'SSH_TEST_PATH_MISSING': 'all', 'SSH_TEST_IDENTITY_ERROR': '1'}),
                                  ('101', {'SSH_TEST_PATH_MISSING': 'all', 'SSH_TEST_IDENTITY_LENGTH': '1'})):
            with self.subTest(argument=argument, changes=changes):
                result = subprocess.run([str(self.inspector), argument], env=dict(environment, **changes),
                                        capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
