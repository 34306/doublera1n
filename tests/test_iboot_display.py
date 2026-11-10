import struct
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import patch_iboot


def put(image, offset, word):
    struct.pack_into('<I', image, offset, word)


def display_sequence(image, offset):
    initialized = offset - 0x48
    put(image, initialized, 0x52800028)
    words = [
        0x394A6E88,
        0x370000C8,
        0x52800E20, 0x52800021,
        0x94000000 | ((0xD00 - offset) // 4),
        0x94000000 | ((0xD40 - offset - 4) // 4),
        0x34000000 | (((initialized - offset - 8) // 4 & 0x7FFFF) << 5),
        0x52800028, 0x390A6E88,
        0x52800000,
        0xA9417BFD, 0xA8C24FF4, 0xD65F0FFF,
    ]
    for index, word in enumerate(words):
        put(image, offset - 16 + 4 * index, word)


class IbssDisplayTests(unittest.TestCase):
    def setUp(self):
        self.image = bytearray(4096)
        self.power = 0x200
        display_sequence(self.image, self.power)
        context = patch.object(patch_iboot._layout, 'TEXT_END', len(self.image))
        context.start()
        self.addCleanup(context.stop)

    def test_only_display_call_changes_power_and_epilogue_are_preserved(self):
        before = bytes(self.image)
        patch_iboot.patch_ibss_skip_display_init(self.image, [])
        expected = bytearray(before)
        put(expected, self.power + 4, 0x52800020)
        self.assertEqual(self.image, expected)

    def test_duplicate_sequences_are_rejected_without_mutation(self):
        display_sequence(self.image, 0x400)
        before = bytes(self.image)
        with self.assertRaisesRegex(SystemExit, 'expected one guarded call'):
            patch_iboot.patch_ibss_skip_display_init(self.image, [])
        self.assertEqual(self.image, before)

    def test_different_state_byte_is_rejected(self):
        put(self.image, self.power + 16, 0x390A7288)
        with self.assertRaisesRegex(SystemExit, 'expected one guarded call'):
            patch_iboot.patch_ibss_skip_display_init(self.image, [])

    def test_changed_branch_destination_is_rejected(self):
        put(self.image, self.power - 12, 0x370000E8)
        with self.assertRaisesRegex(SystemExit, 'expected one guarded call'):
            patch_iboot.patch_ibss_skip_display_init(self.image, [])

    def test_changed_power_arguments_are_rejected(self):
        put(self.image, self.power - 8, 0x52800E40)
        with self.assertRaisesRegex(SystemExit, 'expected one guarded call'):
            patch_iboot.patch_ibss_skip_display_init(self.image, [])

    def test_already_patched_input_is_rejected(self):
        patch_iboot.patch_ibss_skip_display_init(self.image, [])
        with self.assertRaisesRegex(SystemExit, 'expected one guarded call'):
            patch_iboot.patch_ibss_skip_display_init(self.image, [])


if __name__ == '__main__':
    unittest.main()
