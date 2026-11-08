"""Objective-C metadata reader for arm64e Mach-O executables.

Two facts are recovered, not a class dump:
  * methods(selector)         which implementations belong to a named selector (relative method lists:
                              signed 32-bit name / implementation displacements, each relative to its own field);
  * selector_stubs(selector)  which optimized objc_msgSend$selector stubs (`ADRP X1,page ; LDR X1,[X1,#off]`)
                              load that selector's reference slot.
Selector references are dyld chained rebases (DYLD_CHAINED_PTR_ARM64E); chained_rebase_target decodes one.

API
    ObjCMethod(selector, entry_offset, implementation_offset, implementation_address)
    ObjCSelectorStub(selector_reference_offset, stub_offset, stub_address)
    ObjCMetadata(image)                    .image, .layout (MachOLayout)
      .methods(selector) -> [ObjCMethod]                 sorted by implementation offset
      .selector_stubs(selector) -> [ObjCSelectorStub]    sorted by stub offset
      .selector_references(selector) -> [file offset]    __objc_selrefs slots that rebase to the selector name
      .chained_rebase_target(offset) -> address | None   target of a local chained rebase (None for binds)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    from . import core                     # imported as a package
except ImportError:                        # flat import: the package directory is on sys.path
    import core

ARM64, BinaryImage, MachOLayout, PatchfinderError = core.ARM64, core.BinaryImage, core.MachOLayout, core.PatchfinderError
INT64_MAX, MASK64, s32 = core.INT64_MAX, core.MASK64, core.s32

__all__ = ['ObjCMethod', 'ObjCSelectorStub', 'ObjCMetadata']


@dataclass(frozen=True)
class ObjCMethod:
    selector: str
    entry_offset: int
    implementation_offset: int
    implementation_address: int


@dataclass(frozen=True)
class ObjCSelectorStub:
    selector_reference_offset: int
    stub_offset: int
    stub_address: int


def _adding(displacement: int, address: int) -> Optional[int]:
    if address > INT64_MAX:
        return None
    result = address + displacement
    return result if result >= 0 else None


class ObjCMetadata:
    def __init__(self, image: BinaryImage):
        self.image = image
        self.layout = MachOLayout.of(image)
        self._name_index: Optional[Dict[int, List[int]]] = None
        self._selref_targets: Optional[List[Tuple[int, Optional[int]]]] = None
        self._image_base: Optional[int] = None
        self._image_base_known = False

    # -- methods -------------------------------------------------------------------------------------------

    def _method_name_index(self, method_list) -> Dict[int, List[int]]:
        """name-field target address -> method-entry offsets, for every 4-aligned position in __objc_methlist
        (each position is a candidate entry; the index is built once per image and shared by all lookups)."""
        if self._name_index is None:
            index: Dict[int, List[int]] = {}
            read = self.image.read_u32
            virtual_address = self.layout.virtual_address
            r = method_list.file_range
            for entry_offset in range((r.start + 3) & ~3, r.stop - 12 + 1, 4):
                field_address = virtual_address(entry_offset)
                if field_address is None:
                    continue
                target = _adding(s32(read(entry_offset)), field_address)
                if target is not None:
                    index.setdefault(target, []).append(entry_offset)
            self._name_index = index
        return self._name_index

    def methods(self, selector: str) -> List[ObjCMethod]:
        method_list = self.layout.section('__objc_methlist', segment='__TEXT')
        if method_list is None:
            raise PatchfinderError.invalid_fixture('Mach-O has no __TEXT,__objc_methlist')
        references = self.selector_references(selector)
        reference_addresses = {a for a in (self.layout.virtual_address(o) for o in references) if a is not None}
        if not reference_addresses:
            raise PatchfinderError.missing_anchor(selector)

        index = self._method_name_index(method_list)
        entries = sorted(e for address in reference_addresses for e in index.get(address, ()))
        matches = set()
        for entry_offset in entries:
            # The implementation displacement is relative to its own field (entry + 8).
            implementation_field = entry_offset + 8
            displacement = s32(self.image.read_u32(implementation_field))
            field_address = self.layout.virtual_address(implementation_field)
            if field_address is None:
                continue
            implementation_address = _adding(displacement, field_address)
            if implementation_address is None:
                continue
            implementation_offset = self.layout.file_offset(implementation_address)
            if implementation_offset is None or not any(
                    implementation_offset in r for r in self.layout.executable_file_ranges):
                continue
            matches.add(ObjCMethod(selector, entry_offset, implementation_offset, implementation_address))
        return sorted(matches, key=lambda m: (m.implementation_offset, m.entry_offset))

    # -- selector stubs ------------------------------------------------------------------------------------

    def selector_stubs(self, selector: str) -> List[ObjCSelectorStub]:
        stubs = self.layout.section('__objc_stubs', segment='__TEXT')
        if stubs is None:
            raise PatchfinderError.invalid_fixture('Mach-O has no __TEXT,__objc_stubs')
        references = self.selector_references(selector)
        by_address: Dict[int, int] = {}
        for offset in references:
            address = self.layout.virtual_address(offset)
            if address is not None:
                by_address[address] = offset

        matches = set()
        # ADRP X1,<page> ; LDR X1,[X1,#imm]  (page and offset free, both registers X1)
        for offset in self.image.find_masked((0x9000_0001, 0xF940_0021), (0x9F00_001F, 0xFFC0_03FF),
                                             (stubs.file_range,)):
            instruction_address = self.layout.virtual_address(offset)
            if instruction_address is None:
                continue
            adrp = self.image.read_u32(offset)
            load = self.image.read_u32(offset + 4)
            reference_address = (ARM64.adrp_target(adrp, instruction_address)
                                 + ((load >> 10) & 0xFFF) * 8) & MASK64
            reference_offset = by_address.get(reference_address)
            if reference_offset is None:
                continue
            matches.add(ObjCSelectorStub(reference_offset, offset, instruction_address))
        return sorted(matches, key=lambda s: (s.stub_offset, s.selector_reference_offset))

    # -- selector references -------------------------------------------------------------------------------

    def selector_references(self, selector: str) -> List[int]:
        """__DATA,__objc_selrefs slots whose chained rebase resolves to `selector` in __TEXT,__objc_methname."""
        method_names = self.layout.section('__objc_methname', segment='__TEXT')
        selector_references = self.layout.section('__objc_selrefs', segment='__DATA')
        if method_names is None or selector_references is None:
            raise PatchfinderError.invalid_fixture('Mach-O lacks Objective-C selector sections')

        string_offsets = [o for o in self.image.find_all_utf8(selector, nul_terminated=True)
                          if o in method_names.file_range]
        if not string_offsets:
            raise PatchfinderError.missing_anchor(selector)
        string_addresses = {a for a in (self.layout.virtual_address(o) for o in string_offsets) if a is not None}
        if len(string_addresses) != len(string_offsets):
            raise PatchfinderError.invalid_fixture('selector string is not mapped')

        if self._selref_targets is None:
            r = selector_references.file_range
            self._selref_targets = [(offset, self.chained_rebase_target(offset))
                                    for offset in range(r.start, r.stop - 8 + 1, 8)]
        return [offset for offset, target in self._selref_targets if target in string_addresses]

    def chained_rebase_target(self, offset: int) -> Optional[int]:
        """Target of a local DYLD_CHAINED_PTR_ARM64E rebase at `offset`; None for binds or unmapped targets."""
        raw = self.image.read_u64(offset)
        is_authenticated = bool(raw >> 63)
        is_bind = bool((raw >> 62) & 1)
        if is_bind:
            return None
        if not self._image_base_known:
            bases = [s.virtual_address for s in self.layout.segments if s.file_size != 0]
            self._image_base = min(bases) if bases else None
            self._image_base_known = True
        if self._image_base is None:
            return None
        # Authenticated rebases carry a 32-bit target, plain ones 43 bits; next/diversity/high8 are masked away.
        target = raw & 0xFFFF_FFFF if is_authenticated else raw & 0x7FF_FFFF_FFFF
        address = self._image_base + target
        return address if self.layout.file_offset(address) is not None else None
