import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import patch_iboot


class BootargsTests(unittest.TestCase):
    def setUp(self):
        self.raw = bytearray(b'\xA5' * 0x5000)
        self.base = 0x19C050000
        for off, value in ((0x380, self.base), (0x390, self.base + 0x3500),
                           (0x398, self.base + 0x4000)):
            struct.pack_into('<Q', self.raw, off, value)
        self.raw[0x1FC0:0x2030] = bytes(0x70)
        self.raw[0x3500:0x4000] = bytes(0xB00)
        self.site = 0x800
        self.raw[0x24FF:0x2503] = b'\0%s\0'
        words = (patch_iboot.enc_adrp(2, self.site, 0x2500),
                 patch_iboot.enc_add_imm(2, 2, 0x500),
                 0x910003E0, 0x52808001, 0x94000000)
        struct.pack_into('<5I', self.raw, self.site, *words)

    def test_literal_and_reference_change_without_touching_table(self):
        before = bytes(self.raw)
        literal = b'rd=md0 -v wdt=-1 debug=0x2014e\0'
        slot = patch_iboot.patch_bootargs(self.raw, literal[:-1].decode(), [])
        self.assertGreaterEqual(slot, 0x3510)
        self.assertLessEqual(slot + len(literal), 0x3FF0)
        self.assertEqual(self.raw[0x1FC0:0x2030], before[0x1FC0:0x2030])
        target = (patch_iboot.adrp_target(patch_iboot.u32(self.raw, self.site), self.site) +
                  patch_iboot.add_imm(patch_iboot.u32(self.raw, self.site + 4)))
        self.assertEqual(target, slot)
        self.assertEqual(self.raw[target:target + len(literal)], literal)
        expected = bytearray(before)
        expected[self.site:self.site + 8] = self.raw[self.site:self.site + 8]
        expected[slot:slot + len(literal)] = literal
        self.assertEqual(self.raw, expected)

    def test_occupied_gap_is_rejected_without_fallback_or_mutation(self):
        self.raw[0x3600] = 1
        before = bytes(self.raw)
        with self.assertRaisesRegex(SystemExit, 'gap is not empty'):
            patch_iboot.patch_bootargs(self.raw, 'rd=md0', [])
        self.assertEqual(self.raw, before)

    def test_short_gap_is_rejected_even_with_room_in_the_table(self):
        struct.pack_into('<Q', self.raw, 0x390, self.base + 0x3FF0)
        with self.assertRaisesRegex(SystemExit, 'no room'):
            patch_iboot.patch_bootargs(self.raw, 'rd=md0', [])

    def test_invalid_header_boundaries_are_rejected(self):
        for content_end, data_start in ((0x4000, 0x3500), (0x3500, 0x4001), (0x3500, 0x6000)):
            with self.subTest(content_end=content_end, data_start=data_start):
                struct.pack_into('<Q', self.raw, 0x390, self.base + content_end)
                struct.pack_into('<Q', self.raw, 0x398, self.base + data_start)
                with self.assertRaisesRegex(SystemExit, 'invalid read-only/data boundaries'):
                    patch_iboot.bootargs_slot(self.raw, 32)

    def test_truncated_header_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, 'truncated'):
            patch_iboot.bootargs_slot(bytes(0x300), 32)


if __name__ == '__main__':
    unittest.main()
