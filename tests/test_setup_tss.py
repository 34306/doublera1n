import io
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from hashlib import sha384
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'lib')]
from pyimg4 import IM4M, IM4P, IMG4, ManifestImageProperties, ManifestProperty
import dualboot
import precheck
from setup_ticket import SetupError, validate_setup_session


class SetupTssTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / 'build/ipsw'
        self.source.mkdir(parents=True)
        (self.root / 'out').mkdir()
        self.ecid = '0123456789abcdef'
        self.device = {'MODE': 'DFU', 'PWND': 'usbliter8', 'ECID': self.ecid, 'NONC': '11' * 20}
        self.profile = {'board': 'd421ap', 'cpid': '0x8030', 'bdid': '0x06', 'build': '24B119',
                        'product_types': ['iPhone12,3'], 'version': '27.2'}
        self.ws = SimpleNamespace(ecid=self.ecid, profile=self.profile,
                                  p=lambda *parts: str(self.root.joinpath(*parts)))
        self.sep = IM4P(fourcc='rsep', payload=b'exact d421ap RestoreSEP')
        self.sep_digest = sha384(self.sep.output()).digest()
        self.sep.fourcc = 'sepi'
        self.correct_sep = self.source / 'sep-d421.im4p'
        self.correct_sep.write_bytes(self.sep.output())
        (self.source / 'sep-d431.im4p').write_bytes(b'wrong board firmware')
        self.ticket = IM4M()
        for key, value in [('ECID', int(self.ecid, 16)), ('BNCH', bytes.fromhex(self.device['NONC'])),
                           ('CHIP', 0x8030), ('BORD', 6)]:
            self.ticket.add_property(ManifestProperty(fourcc=key, value=value))
        image = ManifestImageProperties(fourcc='rsep')
        image.add_property(ManifestProperty(fourcc='DGST', value=self.sep_digest))
        self.ticket.add_image_properties(image)
        self.ticket._signature = b'offline parser fixture'
        self.ticket._certificates = b'offline parser fixture'
        identities = []
        for board, filename in [('d431ap', 'sep-d431.im4p'), ('d421ap', 'sep-d421.im4p')]:
            identities.append({'Info': {'DeviceClass': board, 'RestoreBehavior': 'Erase'},
                               'Manifest': {'RestoreSEP': {'Info': {'Path': filename}}}})
        (self.source / 'BuildManifest.plist').write_bytes(plistlib.dumps({'BuildIdentities': identities}))
        self.outputs = (self.root / 'out/apticket.im4m', self.root / 'out/rsep.img4')
        for path in self.outputs:
            path.write_bytes(b'cached data from an earlier DFU session')
        self.calls = []

    def run_tool(self, *args, **kwargs):
        self.calls.append(args)
        if str(args[1]).endswith('get_apticket.py'):
            self.assertEqual(args[-2:], ('--behavior', 'Erase'))
            Path(args[3]).write_bytes(self.ticket.output())
        else:
            self.assertTrue(str(args[1]).endswith('mkimg4.py'))
            self.assertEqual(Path(args[2]), self.correct_sep)
            image = IM4P(Path(args[2]).read_bytes())
            image.fourcc = 'rsep'
            Path(args[4]).write_bytes(IMG4(im4p=image, im4m=self.ticket).output())
        return SimpleNamespace(returncode=0)

    def prepare(self, device=None):
        with patch.object(precheck, 'apple_build', return_value={'signed': True}), \
                patch.object(dualboot, 'run', side_effect=self.run_tool), \
                patch.object(dualboot, 'irec_query', return_value=device or self.device), \
                redirect_stdout(io.StringIO()):
            dualboot.prepare_tickets(self.ws)

    def test_cached_files_are_refreshed_and_the_manifest_selects_the_correct_board(self):
        self.prepare()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.outputs[0].read_bytes(), self.ticket.output())
        self.assertEqual(IMG4(self.outputs[1].read_bytes()).im4p.fourcc, 'rsep')
        self.assertEqual([path.stat().st_mode & 0o777 for path in self.outputs], [0o600, 0o600])
        self.assertFalse(list((self.root / 'out').glob('setup-ticket-*')))

    def test_changed_nonce_stops_without_replacing_either_cached_file(self):
        previous = [p.read_bytes() for p in self.outputs]
        with self.assertRaises(SystemExit):
            self.prepare(dict(self.device, NONC='22' * 20))
        self.assertEqual([p.read_bytes() for p in self.outputs], previous)
        self.assertFalse(list((self.root / 'out').glob('setup-ticket-*')))

    def test_a_tss_failure_preserves_the_previous_ticket_pair(self):
        previous = [p.read_bytes() for p in self.outputs]
        with patch.object(precheck, 'apple_build', return_value={'signed': True}), \
                patch.object(dualboot, 'run', return_value=SimpleNamespace(returncode=1, stdout='', stderr='denied')), \
                redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                dualboot.prepare_tickets(self.ws)
        self.assertEqual([p.read_bytes() for p in self.outputs], previous)

    def test_wrong_phone_and_non_pwned_dfu_are_rejected(self):
        for device in (dict(self.device, ECID='1'), dict(self.device, PWND=''), dict(self.device, MODE='Recovery')):
            with self.subTest(device=device), self.assertRaises(SetupError):
                validate_setup_session(self.ticket.output(), device, self.ecid, self.profile)

    def test_wrong_restore_sep_digest_is_rejected_before_publishing_files(self):
        previous = [p.read_bytes() for p in self.outputs]
        image = self.ticket.images[0]
        image.remove_property(fourcc='DGST')
        image.add_property(ManifestProperty(fourcc='DGST', value=bytes(48)))
        with self.assertRaises(SystemExit):
            self.prepare()
        self.assertEqual([p.read_bytes() for p in self.outputs], previous)


if __name__ == '__main__':
    unittest.main()
