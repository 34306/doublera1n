import io
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'lib'))
from pyimg4 import Compression, IM4P, IMG4
import dualboot
import dt_patch
from test_setup_ticket import fixture


class SetupChainTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for directory in ('build/ipsw', 'out', 'build/chain'):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.ws = SimpleNamespace(
            p=lambda *parts: str(self.root.joinpath(*parts)),
            profile={'board': 'n104ap'},
        )
        self.ibss = b'STOCK iBSS ' * 2048
        self.ibec = b'STOCK iBEC ' * 2048
        components = {}

        def component(key, tag, data, compressed=False):
            image = IM4P(fourcc=tag, payload=data)
            if compressed:
                image.payload.compress(Compression.LZFSE)
            path = key.replace(',', '_') + '.im4p'
            (self.root / 'build/ipsw' / path).write_bytes(image.output())
            components[key] = {'Info': {'Path': path}}

        component('iBSS', 'ibss', self.ibss)
        component('iBEC', 'ibec', self.ibec)
        component('RestoreLogo', 'logo', b'logo')
        component('StaticTrustCache', 'trst', b'system cache must not be sent')

        def prop(name, value):
            return [name.encode().ljust(32, b'\0'), len(value), value.ljust((len(value) + 3) & ~3, b'\0')]

        defaults = [[prop('name', b'defaults\0'), prop('content-protect', b'\x01\0\0\0')], []]
        tree = [[prop('name', b'device-tree\0')], [defaults]]
        component('DeviceTree', 'dtre', dt_patch.ser(tree) + bytes(8192), compressed=True)
        manifest = {'BuildIdentities': [{
            'Info': {'DeviceClass': 'n104ap', 'RestoreBehavior': 'Erase'},
            'Manifest': components,
        }]}
        (self.root / 'build/ipsw/BuildManifest.plist').write_bytes(plistlib.dumps(manifest))
        _, tickets = fixture()
        (self.root / 'out/apticket.im4m').write_bytes(next(iter(tickets.values())))
        for name in ('out/rsep.img4', 'build/setuptc-install.img4', 'build/setuprd-install.img4'):
            (self.root / name).write_bytes(b'copy-only fixture')

    def prepare(self):
        self.patch_calls = []
        def patch_image(*args, **kwargs):
            self.patch_calls.append(args)
            options = next(arg for arg in args if str(arg).startswith('--boot-args='))
            Path(args[-1]).write_bytes(Path(args[-2]).read_bytes() + options.encode() + b'\0')

        with patch.object(dualboot, 'run', side_effect=patch_image), redirect_stdout(io.StringIO()):
            dualboot.prepare_setup_iboot(self.ws)

    def test_n104_display_handoff_is_applied_only_to_ibss(self):
        self.prepare()
        by_source = {Path(args[-2]).name: args for args in self.patch_calls}
        self.assertIn('--ibss-skip-display-init', by_source['iBSS.stock.raw'])
        self.assertNotIn('--ibss-skip-display-init', by_source['iBEC.stock.raw'])

    def test_assembled_ibec_uses_its_own_payload_and_only_restore_cache(self):
        self.prepare()
        (self.root / 'build/chain/StaticTrustCache.img4').write_bytes(b'stale artifact')
        env = dict(os.environ, OSB_WORK=str(self.root / 'build'), OSB_OUT=str(self.root / 'out'),
                   OSB_IPSW=str(self.root / 'build/ipsw'), OSB_BOARD='n104ap')
        result = subprocess.run([sys.executable, str(ROOT / 'lib/mk_chain.py'), 'install'],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        chain = self.root / 'build/chain'
        image = IMG4((chain / 'iBEC.img4').read_bytes()).im4p
        image.payload.decompress()
        self.assertEqual(image.fourcc, 'ibec')
        self.assertEqual(image.payload.output().data, (self.root / 'out/iBEC.setup.raw').read_bytes())
        self.assertTrue(image.payload.output().data.startswith(self.ibec))
        self.assertTrue((chain / 'iBSS.raw').read_bytes().startswith(self.ibss))
        self.assertFalse((chain / 'StaticTrustCache.img4').exists())
        self.assertTrue((chain / 'RestoreTrustCache.img4').is_file())
        self.assertEqual(IMG4((chain / 'RestoreLogo.img4').read_bytes()).im4p.fourcc, 'rlgo')

    def test_setup_rebuilds_existing_bootloader_images(self):
        self.prepare()
        for name in ('iBSS.setup.raw', 'iBEC.setup.raw'):
            (self.root / 'out' / name).write_bytes(b'old image serial=3')
        self.prepare()
        for name in ('iBSS.setup.raw', 'iBEC.setup.raw'):
            data = (self.root / 'out' / name).read_bytes()
            self.assertNotIn(b'serial=3', data)
            self.assertIn(b'rd=md0 -v', data)


if __name__ == '__main__':
    unittest.main()
