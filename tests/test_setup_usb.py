import binascii
import hashlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from setup_usb import read_snapshot, ticket_from_transcript
from test_setup_ticket import ECID, PROFILE, fixture


def transcript_for(log, ticket):
    lines = log.decode().splitlines()
    out = []
    for line in lines:
        out.append(f'[rdsetup] {line}\n'.encode())
        if line.startswith('TICKET dir='):
            for offset in range(0, len(ticket), 48):
                block = ticket[offset:offset + 48]
                out.append(f'TKT {offset:05x} {block.hex()} {binascii.crc32(block):08x}\n'.encode())
    out.append(b'[rdsetup] ===== SETUP DONE =====\n')
    return b''.join(out)


class FakeConnection:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, timeout):
        pass

    def makefile(self, mode):
        return io.BytesIO(self.data)


class UsbSetupTests(unittest.TestCase):
    def test_reassembles_real_ticket_output(self):
        log, files = fixture()
        ticket = next(iter(files.values()))
        directory, got = ticket_from_transcript(None, transcript_for(log, ticket), ECID, PROFILE)
        self.assertEqual(got, ticket)
        self.assertEqual(directory, hashlib.sha384(ticket).hexdigest().upper())

    def test_corrupted_chunk_is_rejected(self):
        log, files = fixture()
        data = transcript_for(log, next(iter(files.values())))
        data = data.replace(b'TKT 00000 ', b'TKT 00000 ff', 1)
        with self.assertRaises(ValueError):
            ticket_from_transcript(None, data, ECID, PROFILE)

    def test_rerun_uses_prior_copy_result(self):
        prior, files = fixture()
        ticket = next(iter(files.values()))
        fetch = prior.replace(b'  copyfile -> 0 (ok), files=42, skipped dirs=0\n',
                              b'DataB already set up - template copy skipped\n')
        directory, got = ticket_from_transcript(prior, transcript_for(fetch, ticket), ECID, PROFILE)
        self.assertEqual(got, ticket)
        self.assertEqual(directory, hashlib.sha384(ticket).hexdigest().upper())

    def test_rerun_rejects_failed_prior_copy(self):
        prior, files = fixture(copied=False)
        ticket = next(iter(files.values()))
        fetch, _ = fixture()
        fetch = fetch.replace(b'  copyfile -> 0 (ok), files=42, skipped dirs=0\n',
                              b'DataB already set up - template copy skipped\n')
        with self.assertRaisesRegex(ValueError, 'copy'):
            ticket_from_transcript(prior, transcript_for(fetch, ticket), ECID, PROFILE)

    def test_reads_framed_prior_and_current_logs(self):
        prior, now = b'prior\n', b'[rdsetup] running\n'
        frame = f'DBUSB1 {len(prior)} {len(now)} 0\n'.encode() + prior + now
        with patch('setup_usb.socket.create_connection', return_value=FakeConnection(frame)):
            self.assertEqual(read_snapshot(), (prior, now))


if __name__ == '__main__':
    unittest.main()
