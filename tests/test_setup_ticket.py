import binascii
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from setup_ticket import SetupError, select_ticket


ECID = '0123456789abcdef'
PROFILE = {'build': '24B156', 'cpid': '0x8030', 'bdid': '0x04'}


def fixture(ecid=int(ECID, 16), build='24B156', copied=True):
    from pyimg4 import IM4M, ManifestImageProperties, ManifestProperty
    manifest = IM4M()
    for key, value in [('ECID', ecid), ('CHIP', 0x8030), ('BORD', 4)]:
        manifest.add_property(ManifestProperty(fourcc=key, value=value))
    image = ManifestImageProperties(fourcc='krnl')
    image.add_property(ManifestProperty(fourcc='DGST', value=b'0' * 48))
    manifest.add_image_properties(image)
    manifest._signature = b'signature-for-parser-test'
    manifest._certificates = b'certificate-for-parser-test'
    ticket = manifest.output()
    digest = hashlib.sha384(ticket).hexdigest().upper()
    crc = f'{binascii.crc32(ticket):08x}'
    log = ('===== dualboot setup ramdisk v3 (INSTALL) =====\n'
           f'SYSBUILD {build} SYSVER 27.2.1\n'
           + ('  copyfile -> 0 (ok), files=42, skipped dirs=0\n' if copied else '  copyfile -> 1 (error)\n')
           + f'TICKET dir={digest} len={len(ticket)} sha384={digest} crc={crc}\n'
           + f'TICKET END {digest}\n'
           + f'saved /mnt2/jb/apticket-{digest[:16]}.der\n'
           + 'tickets dumped: 1\n').encode()
    return log, {f'apticket-{digest[:16]}.der': ticket}


class SetupTicketTests(unittest.TestCase):
    def test_matching_ticket_and_completed_copy(self):
        log, files = fixture()
        directory, ticket = select_ticket(log, files, ECID, PROFILE)
        self.assertEqual(directory, hashlib.sha384(ticket).hexdigest().upper())

    def test_wrong_phone_is_rejected(self):
        log, files = fixture(ecid=1)
        with self.assertRaisesRegex(SetupError, 'ECID'):
            select_ticket(log, files, ECID, PROFILE)

    def test_wrong_build_is_rejected(self):
        log, files = fixture(build='24B119')
        with self.assertRaisesRegex(SetupError, 'build'):
            select_ticket(log, files, ECID, PROFILE)

    def test_incomplete_copy_is_rejected(self):
        log, files = fixture(copied=False)
        with self.assertRaisesRegex(SetupError, 'copy'):
            select_ticket(log, files, ECID, PROFILE)

    def test_corrupted_ticket_is_rejected(self):
        log, files = fixture()
        name = next(iter(files))
        files[name] = files[name][:-1] + bytes([files[name][-1] ^ 1])
        with self.assertRaisesRegex(SetupError, 'SHA-384'):
            select_ticket(log, files, ECID, PROFILE)

    def test_rerun_fetch_log_can_supply_ticket(self):
        setup, files = fixture()
        setup = setup.split(b'TICKET dir=', 1)[0] + b'tickets dumped: 0\n'
        fetch, _ = fixture()
        fetch = fetch.replace(b'  copyfile -> 0 (ok), files=42, skipped dirs=0\n',
                              b'DataB already set up - template copy skipped\n')
        directory, ticket = select_ticket(setup, files, ECID, PROFILE, fetch)
        self.assertEqual(directory, hashlib.sha384(ticket).hexdigest().upper())

    def test_rerun_does_not_excuse_failed_initial_copy(self):
        setup, files = fixture(copied=False)
        fetch, _ = fixture()
        fetch = fetch.replace(b'  copyfile -> 0 (ok), files=42, skipped dirs=0\n',
                              b'DataB already set up - template copy skipped\n')
        with self.assertRaisesRegex(SetupError, 'copy'):
            select_ticket(setup, files, ECID, PROFILE, fetch)


if __name__ == '__main__':
    unittest.main()
