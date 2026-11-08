"""Binary-analysis foundation for the semantic patch finder.

Everything a resolver needs to turn a firmware file into patch records: payload loading (IM4P / raw Mach-O),
bounds-checked reads, a thin Mach-O 64 segment/section map, ARM64 encoders and decoders, masked instruction
signatures, the kernel profile registry, and the patch-record / error types. Resolver families live in sibling
modules (kernel_restore, kernel_cm, kernel_policy, txm, userland) and import this module as `core`.

Conventions
    * Offsets are payload file offsets (what records carry). Virtual addresses only appear where Mach-O VM
      arithmetic needs them (ADRP, branch targets) and are converted back with MachOLayout.
    * File and address ranges are Python `range` objects: .start inclusive, .stop exclusive, membership via `in`.
    * Addresses and instruction words are plain non-negative Python ints; arithmetic that must wrap like a 64-bit
      register is masked with MASK64.
    * Optional results are None. The usual uniqueness check is `x = only(candidates)` followed by `if x is None`;
      `try_*` helpers return None where their plain counterpart raises.
    * Errors are PatchfinderError instances built with the factory methods; `.case` is a stable camelCase name
      (e.g. 'outOfBounds') and `.fields` holds the details.

API
  Numbers / text
    MASK32, MASK64, s32(v), s64(v)        two's-complement helpers: signed value of the low 32 / 64 bits
    hex64(v) / hex32(v)                    "0x%llx" / "0x%08x"
    hexdata(b) / data_from_hex(s)          lowercase hex encoding / strict even-length hex decoding (None if malformed)
    only(seq)                              the single element, else None
  Errors / records
    PatchfinderError.<case>(...)           out_of_bounds, missing_anchor, ambiguous_anchor,
                                           no_candidate, ambiguous_candidate, invalid_fixture, fixture_mismatch,
                                           invalid_patch, overlapping_patches, preimage_mismatch, disassembly_failed,
                                           unsupported_firmware_profile, invalid_device_tree,
                                           device_tree_verification_failed, invalid_firmware_container
    PatchRecord(id, component, offset, original_bytes, replacement_bytes, summary, evidence)
    PatchRecord.from_words(id=, component=, offset=, original=, replacement=, summary=, evidence=)
                                           one-instruction patch from two 32-bit words (stored little-endian)
    PatchRecord.to_json() / from_json(d)   record <-> JSON dict (camelCase keys, hex byte strings)
    encode_records(records) -> str         sorted-key pretty JSON, same shape as the CLI output
    guarded_apply(records, image) -> PatchApplicationResult   preimage-checked apply
  Image
    BinaryImage(data) / BinaryImage.from_path(p)
      .data (bytes), .count, len(img)
      .bytes_at(off, n)                    bounds-checked slice (PatchfinderError.out_of_bounds)
      .read_u32(off) / .read_u64(off)      little-endian, bounds-checked
      .try_read_u32(off)                   None when out of bounds
      .find_all(needle) / .find_all_utf8(text, nul_terminated=False)   overlapping occurrences
      .u32                                 aligned word view: img.u32[off >> 2] == read_u32(off) for off % 4 == 0
      .words(r)                            aligned word view of range r, base offset (r.start + 3) & ~3
      .find_masked(values, masks, ranges=None) / .find_word(value, mask, ranges=None)
                                           every 4-aligned offset whose words satisfy word & mask == value,
                                           range by range, in order (a byte-regex search, not a per-word Python loop)
      .memo(key, factory)                  per-image cache for derived data (image bytes are immutable)
    aligned_offsets(r, width=4)            the canonical scan loop: offsets (r.start+3)&~3, +4 .. while off+width <= r.stop
  ARM64 (namespace class)
    constants nop, mov_x0_zero, mov_x0_one, mov_w0_one, mov_w0_zero, ret, pacibsp, bti_c
    encode_adrp(register, instruction_offset, target)         -> word | None
    encode_add_immediate(destination, source, immediate)      -> word | None
    encode_compare_branch(like, at, target)                   -> word | None (retargeted CBZ/CBNZ)
    encode_movz32(destination, immediate) / encode_movk32_shift16(...)
    encode_direct_branch(link, instruction_offset, target)    -> word | None (B or BL)
    adrp_add_references(image, target, maximum_instruction_gap=8, scan_ranges=None, address_for_file_offset=None)
                                           ADRP+ADD pairs materialising `target` (fast scan with the same result
                                           and order as the word-by-word _adrp_add_references_linear)
    is_adrp(w) / is_immediate_add(w)
    adrp_target(w, at) / add_immediate(w)
    branch_link_target(w, at)              BL only
    direct_branch_target(w, at)            B or BL
    conditional_target(w, at)              CBZ/CBNZ/B.cond
    test_branch_target(w, at)              TBZ/TBNZ
    any_conditional_target(w, at)          any of CBZ/CBNZ/B.cond/TBZ/TBNZ
    is_return(w)                           RET/RETAA/RETAB
    function_entry(prologue, image)        BTI C pad before PACIBSP, else the PACIBSP itself
    stub_start(entry, image)               where an entry stub goes: after such a BTI C pad, else `entry`
    function_start(offset, image, layout, limit=0x4000)       nearest entry at or before `offset` -> offset | None
    next_function_start(start, image, layout, limit=0x2000)   next entry after `start`, else the bound
  ADRPAddReference(adrp_offset, add_offset, target)
  Mach-O
    MachOSegment(name, virtual_address, virtual_size, file_offset, file_size, initial_protection)
      .file_range, .is_executable
    MachOSection(segment_name, name, virtual_address, size, file_offset) .file_range
    MachOLayout(image) / MachOLayout.of(image) (cached)       thin LE Mach-O 64 only
      .segments, .sections, .executable_file_ranges
      .virtual_address(file_offset) / .file_offset(virtual_address)   -> address / offset | None
      .segment_containing(file_offset)                        first segment whose file range contains it | None
      .section(named, segment=None)
      .adrp_add_references(to_file_offset)
  Signatures
    MaskedInstructionPattern(name, values, masks)
    MaskedInstructionPattern.from_reference_words(name, words, allow_data_layout_drift=False, ignoring=())
      .matches(image, off) / .unique_match(image, layout) / .matching_word_count(image, off)
      .all_matches(image, ranges)                             every hit, never throws (diagnostics)
      MaskedInstructionPattern.mask(word, allow_data_layout_drift)    relocation mask for one reference word
  Kernel profiles
    ResolverVariantProfile, KernelResolverProfile, KERNEL_RESOLVER_PROFILES
    detect_kernel_profile(image)           unique fingerprint match | None
    TFP0_VARIANT_KEY / TFP0_SIGNATURE_ID / TFP0_PAYLOAD_ID    key, signature id and payload id of the tfp0 variant
  Diagnostics
    BinaryInspector(image)                 segment_report, string_occurrences, references,
                                           function_start, next_function_start, direct_call_targets, objc_methods,
                                           disassembly (built-in decoder, see describe_instruction),
                                           pattern_matches, pattern_word_report
    describe_instruction(word, address)    small text decoder for common branch/ADRP/ADD/MOV forms (diagnostic only;
                                           no full disassembler is available here)
  Loading
    FirmwareArtifact.from_bytes(data) / .from_path(p)          kind 'im4p' | 'raw',
                                           .payload, .fourcc, .container_description
    load_image(path) -> BinaryImage        the bytes every record offset refers to (see "Image loading" below)

Image loading
    The input is parsed as a DER IM4P first (SEQUENCE whose children are "IM4P", fourcc, description, OCTET STRING
    payload, ...). If that fails the file is used as-is (raw payload, e.g. a daemon Mach-O). For an IM4P:
      * payload starts with "complzss" (and is longer than the header): LZSS, decoded by pyimg4. The complzss header
        is 0x180 bytes; the output is cut to the header's uncompressed size.
      * else, a trailing SEQUENCE { INTEGER 1, INTEGER size>0 } compression descriptor: LZFSE, decoded by pyimg4 and
        cut to `size` bytes.
      * else the payload OCTET STRING is used unchanged (also for an LZFSE stream without a descriptor, and for an
        encrypted payload).
    Record offsets are offsets into that decompressed payload (the kernelcache MH_FILESET / TXM Mach-O itself).
    Fat (universal) Mach-O inputs are not thinned: MachOLayout rejects them, exactly like a non-Mach-O. Extract the
    arm64e slice first (`lipo -thin arm64e`) so record offsets are offsets of the file that gets patched.
"""
from __future__ import annotations

import bisect
import functools
import json
import os
import re
import struct
import sys
from array import array
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, NamedTuple, Optional, Sequence, Tuple

MASK32 = 0xFFFF_FFFF
MASK64 = 0xFFFF_FFFF_FFFF_FFFF
INT64_MAX = (1 << 63) - 1
UINT64_MAX = MASK64

_U32 = struct.Struct('<I')
_U64 = struct.Struct('<Q')


# ----------------------------------------------------------------------------------------------------------------
# Numbers and text
# ----------------------------------------------------------------------------------------------------------------

def s32(value: int) -> int:
    """The low 32 bits read as a signed (two's-complement) 32-bit value."""
    value &= MASK32
    return value - (1 << 32) if value & 0x8000_0000 else value


def s64(value: int) -> int:
    """The low 64 bits read as a signed (two's-complement) 64-bit value."""
    value &= MASK64
    return value - (1 << 64) if value >> 63 else value


def hex64(value: int) -> str:
    """0x-prefixed lowercase hex, unpadded."""
    return '0x%x' % value


def hex32(value: int) -> str:
    """0x-prefixed lowercase hex, 8 digits."""
    return '0x%08x' % value


def hexdata(data: bytes) -> str:
    """Lowercase hexadecimal of a byte string."""
    return bytes(data).hex()


_HEX_RE = re.compile(r'(?:[0-9a-fA-F]{2})*')


def data_from_hex(text: str) -> Optional[bytes]:
    """Even-length hex without separators; None when malformed."""
    if len(text) % 2 or not _HEX_RE.fullmatch(text):
        return None
    return bytes.fromhex(text)


def only(items):
    """The single element of a sized collection, else None."""
    items = items if hasattr(items, '__len__') else list(items)
    if len(items) != 1:
        return None
    return next(iter(items))


# ----------------------------------------------------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------------------------------------------------

class PatchfinderError(Exception):
    """A resolver or loader failure. `case` is a stable camelCase failure name; `fields` holds its details."""

    def __init__(self, case: str, description: str, **fields):
        super().__init__(description)
        self.case = case
        self.description = description
        self.fields = fields

    def __str__(self) -> str:
        return self.description

    def __eq__(self, other) -> bool:
        return isinstance(other, PatchfinderError) and (self.case, self.fields) == (other.case, other.fields)

    def __hash__(self) -> int:
        return hash((self.case, self.description))

    @classmethod
    def out_of_bounds(cls, offset: int, length: int) -> 'PatchfinderError':
        return cls('outOfBounds', f'read outside image at {hex64(offset)}, length {length}',
                   offset=offset, length=length)

    @classmethod
    def missing_anchor(cls, anchor: str) -> 'PatchfinderError':
        return cls('missingAnchor', f'missing anchor: {anchor}', anchor=anchor)

    @classmethod
    def ambiguous_anchor(cls, anchor: str, count: int) -> 'PatchfinderError':
        return cls('ambiguousAnchor', f'ambiguous anchor {anchor}: {count} matches', anchor=anchor, count=count)

    @classmethod
    def no_candidate(cls, name: str) -> 'PatchfinderError':
        return cls('noCandidate', f'resolver produced no candidate: {name}', name=name)

    @classmethod
    def ambiguous_candidate(cls, name: str, offsets: Sequence[int]) -> 'PatchfinderError':
        offsets = list(offsets)
        return cls('ambiguousCandidate',
                   f'resolver produced {len(offsets)} candidates for {name}: '
                   + ', '.join(hex64(o) for o in offsets),
                   name=name, offsets=offsets)

    @classmethod
    def invalid_fixture(cls, message: str) -> 'PatchfinderError':
        return cls('invalidFixture', f'invalid fixture: {message}', message=message)

    @classmethod
    def fixture_mismatch(cls, message: str) -> 'PatchfinderError':
        return cls('fixtureMismatch', f'fixture mismatch: {message}', message=message)

    @classmethod
    def invalid_patch(cls, id: str, reason: str) -> 'PatchfinderError':  # noqa: A002 - record id field
        return cls('invalidPatch', f'invalid patch {id}: {reason}', id=id, reason=reason)

    @classmethod
    def overlapping_patches(cls, offset: int) -> 'PatchfinderError':
        return cls('overlappingPatches', f'multiple patches overlap at {hex64(offset)}', offset=offset)

    @classmethod
    def preimage_mismatch(cls, id: str, offset: int, expected: bytes, found: bytes) -> 'PatchfinderError':  # noqa: A002
        return cls('preimageMismatch', f'{id} at {hex64(offset)}: expected {hexdata(expected)}, found {hexdata(found)}',
                   id=id, offset=offset, expected=bytes(expected), found=bytes(found))

    @classmethod
    def disassembly_failed(cls, offset: int, length: int) -> 'PatchfinderError':
        return cls('disassemblyFailed', f'failed to disassemble {length} bytes at {hex64(offset)}',
                   offset=offset, length=length)

    @classmethod
    def unsupported_firmware_profile(cls, resolver: str, profile: str, variant: str) -> 'PatchfinderError':
        return cls('unsupportedFirmwareProfile',
                   f'{resolver} does not support firmware profile {profile} with signature variant {variant}',
                   resolver=resolver, profile=profile, variant=variant)

    @classmethod
    def invalid_device_tree(cls, message: str) -> 'PatchfinderError':
        return cls('invalidDeviceTree', f'invalid DeviceTree: {message}', message=message)

    @classmethod
    def device_tree_verification_failed(cls, path: str) -> 'PatchfinderError':
        return cls('deviceTreeVerificationFailed', f'DeviceTree verification failed for {path}', path=path)

    @classmethod
    def invalid_firmware_container(cls, message: str) -> 'PatchfinderError':
        return cls('invalidFirmwareContainer', f'invalid firmware container: {message}', message=message)


# ----------------------------------------------------------------------------------------------------------------
# Patch records
# ----------------------------------------------------------------------------------------------------------------

def _check_word(name: str, value: int) -> int:
    if not isinstance(value, int) or not 0 <= value <= MASK32:
        raise ValueError(f'{name} must be a 32-bit unsigned instruction word, got {value!r}')
    return value


@dataclass(frozen=True)
class PatchRecord:
    """One guarded byte patch. original/replacement lengths must match (checked when applied)."""
    id: str
    component: str
    offset: int
    original_bytes: bytes
    replacement_bytes: bytes
    summary: str
    evidence: Tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, 'original_bytes', bytes(self.original_bytes))
        object.__setattr__(self, 'replacement_bytes', bytes(self.replacement_bytes))
        object.__setattr__(self, 'evidence', tuple(self.evidence))
        if not isinstance(self.offset, int) or self.offset < 0:
            raise ValueError(f'{self.id}: offset must be a non-negative int, got {self.offset!r}')

    @classmethod
    def from_words(cls, *, id: str, component: str, offset: int, original: int, replacement: int,  # noqa: A002
                   summary: str, evidence: Iterable[str]) -> 'PatchRecord':
        """The common one-instruction ARM64 patch (both words little-endian)."""
        return cls(id=id, component=component, offset=offset,
                   original_bytes=_U32.pack(_check_word('original', original)),
                   replacement_bytes=_U32.pack(_check_word('replacement', replacement)),
                   summary=summary, evidence=tuple(evidence))

    @property
    def original_word(self) -> Optional[int]:
        return _U32.unpack(self.original_bytes)[0] if len(self.original_bytes) == 4 else None

    @property
    def replacement_word(self) -> Optional[int]:
        return _U32.unpack(self.replacement_bytes)[0] if len(self.replacement_bytes) == 4 else None

    def to_json(self) -> dict:
        return {
            'component': self.component,
            'evidence': list(self.evidence),
            'id': self.id,
            'offset': self.offset,
            'originalBytes': hexdata(self.original_bytes),
            'replacementBytes': hexdata(self.replacement_bytes),
            'summary': self.summary,
        }

    @classmethod
    def from_json(cls, value: dict) -> 'PatchRecord':
        original = data_from_hex(value['originalBytes'])
        replacement = data_from_hex(value['replacementBytes'])
        if original is None or replacement is None:
            raise ValueError('patch bytes must be even-length hexadecimal strings')
        return cls(id=value['id'], component=value['component'], offset=int(value['offset']),
                   original_bytes=original, replacement_bytes=replacement,
                   summary=value['summary'], evidence=tuple(value['evidence']))


def encode_records(records: Sequence[PatchRecord]) -> str:
    """Records as pretty, sorted-key JSON (`"key" : value`, escaped slashes, trailing newline)."""
    if not records:
        return '[\n\n]\n'
    text = json.dumps([r.to_json() for r in records], indent=2, sort_keys=True,
                      separators=(',', ' : '), ensure_ascii=False)
    # '/' cannot occur outside a JSON string, so escaping every one only touches string contents.
    return text.replace('/', '\\/') + '\n'


@dataclass(frozen=True)
class PatchApplicationResult:
    data: bytes
    dispositions: Dict[str, str]          # record id -> 'applied' | 'alreadyApplied'


def guarded_apply(records: Sequence[PatchRecord], image) -> PatchApplicationResult:
    """Apply a plan to a copy of `image` (BinaryImage or bytes).

    Each range must hold either its original bytes (patched) or its replacement bytes (already applied); anything
    else aborts the whole plan before a single byte is written.
    """
    if not isinstance(image, BinaryImage):
        image = BinaryImage(image)
    ordered = sorted(records, key=lambda r: r.offset)
    for record in ordered:
        if not record.original_bytes:
            raise PatchfinderError.invalid_patch(record.id, 'empty byte range')
        if len(record.original_bytes) != len(record.replacement_bytes):
            raise PatchfinderError.invalid_patch(record.id, 'original and replacement lengths differ')
    for first, second in zip(ordered, ordered[1:]):
        if first.offset + len(first.replacement_bytes) > second.offset:
            raise PatchfinderError.overlapping_patches(second.offset)
    dispositions: Dict[str, str] = {}
    for record in ordered:
        found = image.bytes_at(record.offset, len(record.original_bytes))
        if found == record.original_bytes:
            dispositions[record.id] = 'applied'
        elif found == record.replacement_bytes:
            dispositions[record.id] = 'alreadyApplied'
        else:
            raise PatchfinderError.preimage_mismatch(record.id, record.offset, record.original_bytes, found)
    output = bytearray(image.data)
    for record in ordered:
        if dispositions[record.id] == 'applied':
            output[record.offset:record.offset + len(record.replacement_bytes)] = record.replacement_bytes
    return PatchApplicationResult(bytes(output), dispositions)


# ----------------------------------------------------------------------------------------------------------------
# Fast masked-word scanning
# ----------------------------------------------------------------------------------------------------------------

def _byte_class(value: int, mask: int) -> Optional[bytes]:
    if mask == 0xFF:
        return b'\\x%02x' % value
    if mask == 0:
        return b'.' if value == 0 else None
    members = [b for b in range(256) if b & mask == value]
    if not members:
        return None
    return b'[' + b''.join(b'\\x%02x' % b for b in members) + b']'


@functools.lru_cache(maxsize=1024)
def _masked_plan(values: Tuple[int, ...], masks: Tuple[int, ...]):
    """(anchor index k, byte regex for words k..n-1) or None when some value has bits outside its mask.

    The regex starts at the most selective word (preferably one whose first byte is fully specified, so the regex
    engine can use a literal-prefix search); words before the anchor are checked in Python per hit.
    """
    if any(value & ~mask & MASK32 for value, mask in zip(values, masks)):
        return None
    anchor = max(range(len(masks)), key=lambda i: ((masks[i] & 0xFF) == 0xFF, bin(masks[i]).count('1'), -i))
    parts = []
    for value, mask in zip(values[anchor:], masks[anchor:]):
        for shift in (0, 8, 16, 24):
            parts.append(_byte_class((value >> shift) & 0xFF, (mask >> shift) & 0xFF))
    return anchor, re.compile(b''.join(parts), re.DOTALL)


def _scan_regex(regex, data: bytes, start: int, stop: int) -> Iterator[int]:
    """4-aligned match starts of `regex` in data[start:stop] (matches may overlap)."""
    search = regex.search
    pos = (start + 3) & ~3
    while pos < stop:
        match = search(data, pos, stop)
        if match is None:
            return
        hit = match.start()
        if hit & 3 == 0:
            yield hit
        pos = (hit + 4) & ~3


def aligned_offsets(r: range, width: int = 4) -> range:
    """The canonical scan loop: offsets (lo + 3) & ~3, then every 4 bytes while offset + width <= hi."""
    return range((r.start + 3) & ~3, r.stop - width + 1, 4)


# ----------------------------------------------------------------------------------------------------------------
# BinaryImage
# ----------------------------------------------------------------------------------------------------------------

class BinaryImage:
    """Immutable payload bytes with bounds-checked little-endian reads."""

    __slots__ = ('data', 'u32', '_n4', '_memo')

    def __init__(self, data):
        if not isinstance(data, bytes):
            data = bytes(data)
        self.data = data
        self._n4 = len(data) & ~3
        if sys.byteorder == 'little' and struct.calcsize('I') == 4:
            self.u32 = memoryview(data)[:self._n4].cast('I')
        else:  # pragma: no cover - big-endian hosts
            typecode = 'I' if array('I').itemsize == 4 else 'L'
            words = array(typecode)
            words.frombytes(data[:self._n4])
            if sys.byteorder != 'little':
                words.byteswap()
            self.u32 = words
        self._memo = {}

    @classmethod
    def from_path(cls, path: str) -> 'BinaryImage':
        with open(path, 'rb') as handle:
            return cls(handle.read())

    @property
    def count(self) -> int:
        return len(self.data)

    def __len__(self) -> int:
        return len(self.data)

    def memo(self, key, factory: Callable[[], object]):
        """Cache a value derived from these bytes (e.g. the Mach-O layout or the detected kernel profile)."""
        try:
            return self._memo[key]
        except KeyError:
            value = self._memo[key] = factory()
            return value

    def _checked_start(self, offset: int, length: int) -> int:
        if length < 0 or offset < 0 or offset > len(self.data) or length > len(self.data) - offset:
            raise PatchfinderError.out_of_bounds(offset, length)
        return offset

    def bytes_at(self, offset: int, count: int) -> bytes:
        start = self._checked_start(offset, count)
        return self.data[start:start + count]

    def read_u32(self, offset: int) -> int:
        if offset & 3 == 0 and 0 <= offset < self._n4:
            return self.u32[offset >> 2]
        return _U32.unpack_from(self.data, self._checked_start(offset, 4))[0]

    def try_read_u32(self, offset: int) -> Optional[int]:
        if offset & 3 == 0 and 0 <= offset < self._n4:
            return self.u32[offset >> 2]
        if offset < 0 or offset + 4 > len(self.data):
            return None
        return _U32.unpack_from(self.data, offset)[0]

    def read_u64(self, offset: int) -> int:
        return _U64.unpack_from(self.data, self._checked_start(offset, 8))[0]

    def words(self, r: range):
        """Aligned word view over range r; element i is the word at ((r.start + 3) & ~3) + 4 * i."""
        start = (r.start + 3) & ~3
        stop = min(r.stop, len(self.data))
        return self.u32[start >> 2:max(start, stop) >> 2]

    def find_all(self, needle: bytes) -> List[int]:
        data = self.data
        if not needle or len(needle) > len(data):
            return []
        matches = []
        hit = data.find(needle)
        while hit != -1:
            matches.append(hit)
            hit = data.find(needle, hit + 1)
        return matches

    def find_all_utf8(self, text: str, nul_terminated: bool = False) -> List[int]:
        needle = text.encode('utf-8')
        if nul_terminated:
            needle += b'\0'
        return self.find_all(needle)

    def find_masked(self, values: Sequence[int], masks: Sequence[int],
                    ranges: Optional[Iterable[range]] = None) -> List[int]:
        """Every 4-aligned offset o (range by range, ascending) with read_u32(o + 4i) & masks[i] == values[i]
        for all i and o + 4 * len(values) <= range.stop."""
        values, masks = tuple(v & MASK32 for v in values), tuple(m & MASK32 for m in masks)
        if not values or len(values) != len(masks):
            raise ValueError('values and masks must be non-empty and the same length')
        plan = _masked_plan(values, masks)
        if plan is None:
            return []
        anchor, regex = plan
        if ranges is None:
            ranges = (range(0, len(self.data)),)
        read = self.read_u32
        prefix = tuple(zip(range(0, anchor * 4, 4), values[:anchor], masks[:anchor]))
        hits: List[int] = []
        for r in ranges:
            start = (r.start + 3) & ~3
            for hit in _scan_regex(regex, self.data, start + anchor * 4, min(r.stop, len(self.data))):
                offset = hit - anchor * 4
                if all(read(offset + delta) & mask == value for delta, value, mask in prefix):
                    hits.append(offset)
        return hits

    def find_word(self, value: int, mask: int = MASK32, ranges: Optional[Iterable[range]] = None) -> List[int]:
        return self.find_masked((value,), (mask,), ranges)


# ----------------------------------------------------------------------------------------------------------------
# ARM64
# ----------------------------------------------------------------------------------------------------------------

class ADRPAddReference(NamedTuple):
    adrp_offset: int
    add_offset: int
    target: int


class ARM64:
    """ARM64 instruction encoders/decoders. Addresses are unsigned 64-bit values; branch and ADRP targets wrap
    modulo 2**64."""

    nop = 0xD503_201F          # NOP
    mov_x0_zero = 0xD280_0000  # MOV X0,#0
    mov_x0_one = 0xD280_0020   # MOV X0,#1
    mov_w0_one = 0x5280_0020   # MOV W0,#1
    mov_w0_zero = 0x5280_0000  # MOV W0,#0
    ret = 0xD65F_03C0          # RET
    pacibsp = 0xD503_237F
    bti_c = 0xD503_245F

    # -- encoders --------------------------------------------------------------------------------------------

    @staticmethod
    def encode_adrp(register: int, instruction_offset: int, target: int) -> Optional[int]:
        """ADRP Xn, target@page (validated signed 21-bit page delta)."""
        if not 0 <= register < 32:
            return None
        pc_page = s64(instruction_offset & ~0xFFF)
        target_page = s64(target & ~0xFFF)
        byte_delta = s64(target_page - pc_page)
        if byte_delta % 0x1000:
            return None
        page_delta = byte_delta // 0x1000
        if not -(1 << 20) <= page_delta < (1 << 20):
            return None
        immediate = page_delta & 0x1F_FFFF
        return 0x9000_0000 | ((immediate & 0x3) << 29) | (((immediate >> 2) & 0x7_FFFF) << 5) | register

    @staticmethod
    def encode_add_immediate(destination: int, source: int, immediate: int) -> Optional[int]:
        """64-bit ADD Xd, Xn, #imm12 (no shift)."""
        if not (0 <= destination < 32 and 0 <= source < 32 and 0 <= immediate < 0x1000):
            return None
        return 0x9100_0000 | (immediate << 10) | (source << 5) | destination

    @staticmethod
    def encode_compare_branch(like: int, at: int, target: int) -> Optional[int]:
        """Retarget a CBZ/CBNZ, keeping width, sense and tested register."""
        if like & 0x7E00_0000 != 0x3400_0000:
            return None
        delta = s64(target) - s64(at)
        if delta % 4:
            return None
        words = delta // 4
        if not -(1 << 18) <= words < (1 << 18):
            return None
        return (like & 0xFF00_001F) | ((words & 0x7_FFFF) << 5)

    @staticmethod
    def encode_movz32(destination: int, immediate: int) -> Optional[int]:
        """MOVZ Wd, #imm16."""
        if not 0 <= destination < 32:
            return None
        return 0x5280_0000 | ((immediate & 0xFFFF) << 5) | destination

    @staticmethod
    def encode_movk32_shift16(destination: int, immediate: int) -> Optional[int]:
        """MOVK Wd, #imm16, LSL #16."""
        if not 0 <= destination < 32:
            return None
        return 0x72A0_0000 | ((immediate & 0xFFFF) << 5) | destination

    @staticmethod
    def encode_direct_branch(link: bool, instruction_offset: int, target: int) -> Optional[int]:
        """B (link=False) or BL (link=True) with a checked 26-bit displacement."""
        delta = s64(target) - s64(instruction_offset)
        if delta % 4:
            return None
        words = delta // 4
        if not -(1 << 25) <= words < (1 << 25):
            return None
        return (0x9400_0000 if link else 0x1400_0000) | (words & 0x03FF_FFFF)

    # -- decoders --------------------------------------------------------------------------------------------

    @staticmethod
    def is_adrp(instruction: int) -> bool:
        return instruction & 0x9F00_0000 == 0x9000_0000

    @staticmethod
    def is_immediate_add(instruction: int) -> bool:
        """ADD W/Xd, W/Xn, #imm (opcode-class test only)."""
        return instruction & 0x7F00_0000 == 0x1100_0000

    @staticmethod
    def adrp_target(instruction: int, at: int) -> int:
        encoded = (((instruction >> 5) & 0x7FFFF) << 2) | ((instruction >> 29) & 0x3)
        signed_pages = encoded if encoded & (1 << 20) == 0 else encoded - (1 << 21)
        return (s64(at & ~0xFFF) + (signed_pages << 12)) & MASK64

    @staticmethod
    def add_immediate(instruction: int) -> int:
        immediate = (instruction >> 10) & 0xFFF
        return immediate << 12 if (instruction >> 22) & 1 else immediate

    @staticmethod
    def branch_link_target(instruction: int, at: int) -> Optional[int]:
        """BL only."""
        if instruction & 0xFC00_0000 != 0x9400_0000:
            return None
        encoded = instruction & 0x03FF_FFFF
        signed = encoded if encoded & (1 << 25) == 0 else encoded - (1 << 26)
        return (s64(at) + signed * 4) & MASK64

    @staticmethod
    def direct_branch_target(instruction: int, at: int) -> Optional[int]:
        """B or BL."""
        opcode = instruction & 0xFC00_0000
        if opcode != 0x1400_0000 and opcode != 0x9400_0000:
            return None
        encoded = instruction & 0x03FF_FFFF
        signed = encoded if encoded & (1 << 25) == 0 else encoded - (1 << 26)
        return (s64(at) + signed * 4) & MASK64

    @staticmethod
    def conditional_target(instruction: int, at: int) -> Optional[int]:
        """CBZ/CBNZ (either width) or B.cond."""
        if not (instruction & 0x7E00_0000 == 0x3400_0000 or instruction & 0xFF00_0010 == 0x5400_0000):
            return None
        encoded = (instruction >> 5) & 0x7_FFFF
        signed = encoded if encoded & (1 << 18) == 0 else encoded - (1 << 19)
        return (s64(at) + signed * 4) & MASK64

    @staticmethod
    def test_branch_target(instruction: int, at: int) -> Optional[int]:
        """TBZ/TBNZ (signed imm14)."""
        if instruction & 0x7E00_0000 != 0x3600_0000:
            return None
        encoded = (instruction >> 5) & 0x3FFF
        signed = encoded if encoded & (1 << 13) == 0 else encoded - (1 << 14)
        return (s64(at) + signed * 4) & MASK64

    @staticmethod
    def any_conditional_target(instruction: int, at: int) -> Optional[int]:
        target = ARM64.conditional_target(instruction, at)
        return target if target is not None else ARM64.test_branch_target(instruction, at)

    @staticmethod
    def is_return(instruction: int) -> bool:
        """RET, RETAA, RETAB."""
        return instruction in (0xD65F_03C0, 0xD65F_0BFF, 0xD65F_0FFF)

    # -- ADRP+ADD cross references ---------------------------------------------------------------------------

    @staticmethod
    def adrp_add_references(image: BinaryImage, target: int, maximum_instruction_gap: int = 8,
                            scan_ranges: Optional[Sequence[range]] = None,
                            address_for_file_offset: Optional[Callable[[int], int]] = None
                            ) -> List[ADRPAddReference]:
        """ADRP Xn,page ; (up to gap-1 other instructions) ; ADD Xn,Xn,#imm pairs with page + imm == target.

        `address_for_file_offset` maps an ADRP's file offset to its runtime PC (identity by default, as for flat
        payloads; MachOLayout passes its virtual-address map). Results are ordered range by range, then by ADRP
        offset, then by ADD offset: the same pairs in the same order as the word-by-word
        _adrp_add_references_linear.
        """
        if maximum_instruction_gap <= 0:
            return []
        address = address_for_file_offset or (lambda offset: offset)
        if scan_ranges is None:
            scan_ranges = [range(0, image.count)]
        target &= MASK64
        low = target & 0xFFF
        read = image.read_u32
        references: List[ADRPAddReference] = []
        for r in scan_ranges:
            if r.start >= r.stop:
                continue
            first = (r.start + 3) & ~3
            range_end = min(r.stop, image.count)
            if range_end < 4:
                continue
            last = range_end - 4
            if first > last:
                continue
            # page (4K aligned) + add_immediate == target needs an unshifted imm12 equal to target & 0xFFF, or, only
            # when that is 0, a shifted (LSL #12) immediate. ADD Xn,Xn candidates come from a per-range index.
            unshifted, shifted = ARM64._add_index(image, first, range_end)
            adds = unshifted.get(low, [])
            if low == 0 and shifted:
                adds = sorted(adds + shifted)
            found = []
            for add_offset in adds:
                add = read(add_offset)
                register = add & 0x1F
                immediate = ARM64.add_immediate(add)
                for distance in range(1, maximum_instruction_gap + 1):
                    adrp_offset = add_offset - distance * 4
                    if adrp_offset < first:
                        break
                    adrp = read(adrp_offset)
                    if adrp & 0x9F00_0000 != 0x9000_0000 or adrp & 0x1F != register:
                        continue
                    page = ARM64.adrp_target(adrp, address(adrp_offset))
                    if (page + immediate) & MASK64 == target:
                        found.append(ADRPAddReference(adrp_offset, add_offset, target))
            found.sort()
            references.extend(found)
        return references

    @staticmethod
    def _add_index(image: BinaryImage, first: int, range_end: int):
        """ADD W/Xn,W/Xn,#imm words (destination == source) at 4-aligned offsets in [first + 4, range_end):
        ({imm12: [offsets]} for LSL #0, [offsets] for LSL #12), ascending. Built once per image and range."""
        def build():
            unshifted: Dict[int, List[int]] = {}
            shifted: List[int] = []
            read = image.read_u32
            for offset in image.find_word(0x1100_0000, 0x7F00_0000, (range(first + 4, range_end),)):
                word = read(offset)
                if (word >> 5) & 0x1F != word & 0x1F:
                    continue
                if word & 0x40_0000:
                    shifted.append(offset)
                else:
                    unshifted.setdefault((word >> 10) & 0xFFF, []).append(offset)
            return unshifted, shifted
        return image.memo(('add_index', first, range_end), build)

    # -- function boundaries ---------------------------------------------------------------------------------

    @staticmethod
    def function_entry(prologue: int, image: BinaryImage) -> int:
        """The address a BL targets for the PACIBSP at `prologue`: a preceding BTI C pad, if any."""
        if prologue >= 4 and image.try_read_u32(prologue - 4) == ARM64.bti_c:
            return prologue - 4
        return prologue

    @staticmethod
    def stub_start(entry: int, image: BinaryImage) -> int:
        """Where an entry stub must be written: after a BTI C pad that precedes PACIBSP, else `entry`."""
        if image.try_read_u32(entry) == ARM64.bti_c and image.try_read_u32(entry + 4) == ARM64.pacibsp:
            return entry + 4
        return entry

    @staticmethod
    def function_start(offset: int, image: BinaryImage, layout: 'MachOLayout', limit: int = 0x4000) -> Optional[int]:
        """Nearest PACIBSP-led function entry at or before `offset`, within `limit` and its executable segment.

        The backward scan stops at `floor + 4` (`while cursor >= floor + 4`), so the word at `floor` itself is
        never examined.
        """
        containing = next((r for r in layout.executable_file_ranges if offset in r), None)
        if containing is None:
            return None
        floor = max(containing.start, offset - min(offset - containing.start, limit))
        data = image.data
        end = (offset & ~3) + 4
        while True:
            hit = data.rfind(_PACIBSP_BYTES, floor + 4, end)
            if hit < 0:
                return None
            if hit & 3 == 0:
                return ARM64.function_entry(hit, image)
            end = hit + 3

    @staticmethod
    def next_function_start(start: int, image: BinaryImage, layout: 'MachOLayout', limit: int = 0x2000) -> int:
        """Next function entry strictly after `start` (stepping by 4 from start + 4), bounded by `limit` and the
        containing executable segment; the bound itself when none is found."""
        containing = next((r for r in layout.executable_file_ranges if start in r), None)
        if containing is None:
            return start + limit
        end = min(containing.stop, start + limit)
        data = image.data
        cursor = start + 4
        while cursor < end:
            hit = data.find(_PACIBSP_BYTES, cursor, end + 3)
            if hit < 0:
                return end
            if (hit - start) & 3:
                cursor = hit + 1
                continue
            entry = ARM64.function_entry(hit, image)
            if entry > start:
                return entry
            cursor = hit + 4
        return end


_PACIBSP_BYTES = _U32.pack(ARM64.pacibsp)


def _adrp_add_references_linear(image: BinaryImage, target: int, maximum_instruction_gap: int = 8,
                                scan_ranges: Optional[Sequence[range]] = None,
                                address_for_file_offset: Optional[Callable[[int], int]] = None
                                ) -> List[ADRPAddReference]:
    """Word-by-word version of ARM64.adrp_add_references (slow; used to check that the fast path matches it)."""
    if maximum_instruction_gap <= 0:
        return []
    address = address_for_file_offset or (lambda offset: offset)
    references = []
    for r in scan_ranges if scan_ranges is not None else [range(0, image.count)]:
        if r.start >= r.stop:
            continue
        adrp_offset = (r.start + 3) & ~3
        range_end = min(r.stop, image.count)
        if range_end < 4:
            continue
        last = range_end - 4
        while adrp_offset <= last:
            adrp = image.read_u32(adrp_offset)
            if not ARM64.is_adrp(adrp):
                adrp_offset += 4
                continue
            page = ARM64.adrp_target(adrp, address(adrp_offset))
            register = adrp & 0x1F
            for distance in range(1, maximum_instruction_gap + 1):
                add_offset = adrp_offset + distance * 4
                if add_offset > last:
                    break
                add = image.read_u32(add_offset)
                if not ARM64.is_immediate_add(add):
                    continue
                if add & 0x1F != register or (add >> 5) & 0x1F != register:
                    continue
                resolved = (page + ARM64.add_immediate(add)) & MASK64
                if resolved == target:
                    references.append(ADRPAddReference(adrp_offset, add_offset, resolved))
            adrp_offset += 4
    return references


# ----------------------------------------------------------------------------------------------------------------
# Mach-O layout
# ----------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class MachOSegment:
    name: str
    virtual_address: int
    virtual_size: int
    file_offset: int
    file_size: int
    initial_protection: int

    @property
    def file_range(self) -> range:
        return range(self.file_offset, self.file_offset + self.file_size)

    @property
    def is_executable(self) -> bool:
        return bool(self.initial_protection & 0x4)


@dataclass(frozen=True)
class MachOSection:
    segment_name: str
    name: str
    virtual_address: int
    size: int
    file_offset: int

    @property
    def file_range(self) -> range:
        return range(self.file_offset, self.file_offset + self.size)


def _cstring16(raw: bytes) -> str:
    return raw.split(b'\0', 1)[0].decode('utf-8', 'replace')


class _IntervalIndex:
    """First-match interval lookup; bisect when the non-empty intervals are disjoint, linear otherwise."""

    def __init__(self, intervals: List[Tuple[int, int, int]]):     # (start, stop, payload index), in order
        self.intervals = intervals
        live = sorted((s, e, i) for s, e, i in intervals if s < e)
        disjoint = all(a[1] <= b[0] for a, b in zip(live, live[1:]))
        self.starts = [s for s, _, _ in live] if disjoint else None
        self.live = live

    def find(self, value: int) -> Optional[int]:
        if self.starts is not None:
            position = bisect.bisect_right(self.starts, value) - 1
            if position >= 0:
                start, stop, index = self.live[position]
                if start <= value < stop:
                    return index
            return None
        for start, stop, index in self.intervals:
            if start <= value < stop:
                return index
        return None


class MachOLayout:
    """Segment/section map of a thin, little-endian, 64-bit Mach-O payload (top-level LC_SEGMENT_64 only)."""

    magic64 = 0xFEED_FACF
    segment64 = 0x19

    def __init__(self, image: BinaryImage):
        magic = image.read_u32(0)
        if magic != self.magic64:
            message = 'expected thin little-endian Mach-O 64 payload'
            if magic in (0xBEBA_FECA, 0xBFBA_FECA):
                message += ' (this is a fat/universal Mach-O: extract the arm64e slice first, e.g. lipo -thin arm64e)'
            raise PatchfinderError.invalid_fixture(message)

        command_count = image.read_u32(16)
        command_offset = 32
        segments: List[MachOSegment] = []
        sections: List[MachOSection] = []
        for _ in range(command_count):
            command = image.read_u32(command_offset)
            command_size = image.read_u32(command_offset + 4)
            if command_size < 8 or command_offset + command_size > image.count:
                raise PatchfinderError.invalid_fixture('malformed Mach-O load command')
            if command == self.segment64:
                if command_size < 72:
                    raise PatchfinderError.invalid_fixture('short LC_SEGMENT_64 command')
                name = _cstring16(image.bytes_at(command_offset + 8, 16))
                segment = MachOSegment(
                    name=name,
                    virtual_address=image.read_u64(command_offset + 24),
                    virtual_size=image.read_u64(command_offset + 32),
                    file_offset=image.read_u64(command_offset + 40),
                    file_size=image.read_u64(command_offset + 48),
                    initial_protection=image.read_u32(command_offset + 60),
                )
                if segment.file_offset + segment.file_size > image.count:
                    raise PatchfinderError.invalid_fixture(f'segment {name} extends past end of file')
                segments.append(segment)
                section_count = image.read_u32(command_offset + 64)
                if 72 + section_count * 80 > command_size:
                    raise PatchfinderError.invalid_fixture('section table exceeds LC_SEGMENT_64')
                for index in range(section_count):
                    section_offset = command_offset + 72 + index * 80
                    section = MachOSection(
                        segment_name=_cstring16(image.bytes_at(section_offset + 16, 16)),
                        name=_cstring16(image.bytes_at(section_offset, 16)),
                        virtual_address=image.read_u64(section_offset + 32),
                        size=image.read_u64(section_offset + 40),
                        file_offset=image.read_u32(section_offset + 48),
                    )
                    # Zero-fill sections have no file bytes; keep only those whose (offset, size) fit the file.
                    if section.file_offset + section.size <= image.count:
                        sections.append(section)
            command_offset += command_size

        if not segments:
            raise PatchfinderError.invalid_fixture('Mach-O contains no LC_SEGMENT_64 commands')
        self.image = image
        self.segments: List[MachOSegment] = segments
        self.sections: List[MachOSection] = sections
        self.executable_file_ranges: List[range] = [s.file_range for s in segments if s.is_executable]
        self._by_file = _IntervalIndex([(s.file_offset, s.file_offset + s.file_size, i)
                                        for i, s in enumerate(segments)])
        self._by_address = _IntervalIndex([(s.virtual_address, s.virtual_address + s.file_size, i)
                                           for i, s in enumerate(segments)])

    @classmethod
    def of(cls, image: BinaryImage) -> 'MachOLayout':
        """The layout of `image`, parsed once and cached on the image."""
        return image.memo(('MachOLayout',), lambda: cls(image))

    def segment_containing(self, file_offset: int) -> Optional[MachOSegment]:
        index = self._by_file.find(file_offset)
        return None if index is None else self.segments[index]

    def virtual_address(self, file_offset: int) -> Optional[int]:
        index = self._by_file.find(file_offset)
        if index is None:
            return None
        segment = self.segments[index]
        return segment.virtual_address + (file_offset - segment.file_offset)

    def file_offset(self, virtual_address: int) -> Optional[int]:
        """Only file-backed bytes ([vmaddr, vmaddr + filesize)) map back to a file offset."""
        index = self._by_address.find(virtual_address)
        if index is None:
            return None
        segment = self.segments[index]
        return segment.file_offset + (virtual_address - segment.virtual_address)

    def section(self, named: str, segment: Optional[str] = None) -> Optional[MachOSection]:
        for section in self.sections:
            if section.name == named and (segment is None or section.segment_name == segment):
                return section
        return None

    def adrp_add_references(self, to_file_offset: int) -> List[ADRPAddReference]:
        """ADRP+ADD references (file offsets) to a file offset, using virtual addresses for the arithmetic."""
        target_address = self.virtual_address(to_file_offset)
        if target_address is None:
            raise PatchfinderError.invalid_fixture(
                f'target file offset {hex64(to_file_offset)} is outside mapped segments')

        def address(offset: int) -> int:
            mapped = self.virtual_address(offset)
            return UINT64_MAX if mapped is None else mapped

        return ARM64.adrp_add_references(self.image, target_address, scan_ranges=self.executable_file_ranges,
                                         address_for_file_offset=address)


# ----------------------------------------------------------------------------------------------------------------
# Masked instruction signatures
# ----------------------------------------------------------------------------------------------------------------

class MaskedInstructionPattern:
    """A relocation-tolerant instruction signature: word i matches when word & masks[i] == values[i].

    Masks are bit-selection fields (1 = compare). Only linker-rewritten fields (branch displacements, ADRP pages,
    literal offsets and, with allow_data_layout_drift, unsigned load/store and ADD immediates) are relaxed.
    """

    __slots__ = ('name', 'values', 'masks')

    def __init__(self, name: str, values: Sequence[int], masks: Sequence[int]):
        if not values or len(values) != len(masks):
            raise ValueError('values must be non-empty and match masks')
        self.name = name
        self.values = tuple(values)
        self.masks = tuple(masks)

    @classmethod
    def from_reference_words(cls, name: str, reference_words: Sequence[int], allow_data_layout_drift: bool = False,
                             ignoring: Iterable[int] = ()) -> 'MaskedInstructionPattern':
        """Signature from words of a known-good build: relinked fields masked, `ignoring` indices fully masked."""
        ignored = set(ignoring)
        if not all(0 <= i < len(reference_words) for i in ignored):
            raise ValueError('ignored index outside reference words')
        masks = [0 if i in ignored else cls.mask(word, allow_data_layout_drift)
                 for i, word in enumerate(reference_words)]
        return cls(name, [w & m for w, m in zip(reference_words, masks)], masks)

    @staticmethod
    def mask(word: int, allow_data_layout_drift: bool) -> int:
        if word & 0xFC00_0000 == 0x1400_0000 or word & 0xFC00_0000 == 0x9400_0000:
            return 0xFC00_0000                          # B / BL: opcode only
        if word & 0xFF00_0010 == 0x5400_0000:
            return 0xFF00_001F                          # B.cond: keep condition
        if word & 0x7E00_0000 == 0x3400_0000:
            return 0xFF00_001F                          # CBZ/CBNZ: width, sense, register
        if word & 0x7E00_0000 == 0x3600_0000:
            return 0xFFF8_001F                          # TBZ/TBNZ: also the bit number
        if word & 0x9F00_0000 == 0x9000_0000:
            return 0x9F00_001F                          # ADRP: opcode + destination
        if word & 0x3B00_0000 == 0x1800_0000:
            return 0xFF00_001F                          # literal LDR: operation + destination
        if allow_data_layout_drift and word & 0x3B00_0000 == 0x3900_0000:
            return 0xFFC0_03FF                          # unsigned-offset LDR/STR: field displacement may move
        if allow_data_layout_drift and word & 0xFF80_0000 == 0x9100_0000:
            return 0xFFC0_03FF                          # ADD Xd,Xn,#imm (LSL #0) after an ADRP
        return MASK32

    def matches(self, image: BinaryImage, offset: int) -> bool:
        read = image.read_u32
        for index, (value, mask) in enumerate(zip(self.values, self.masks)):
            if read(offset + index * 4) & mask != value:
                return False
        return True

    def matching_word_count(self, image: BinaryImage, offset: int) -> int:
        read = image.read_u32
        return sum(1 for index, (value, mask) in enumerate(zip(self.values, self.masks))
                   if read(offset + index * 4) & mask == value)

    def all_matches(self, image: BinaryImage, ranges: Iterable[range]) -> List[int]:
        byte_count = len(self.values) * 4
        return image.find_masked(self.values, self.masks,
                                 [r for r in ranges if r.stop - r.start >= byte_count])

    def unique_match(self, image: BinaryImage, layout: MachOLayout) -> int:
        hits = self.all_matches(image, layout.executable_file_ranges)
        if len(hits) == 1:
            return hits[0]
        if not hits:
            raise PatchfinderError.no_candidate(self.name)
        raise PatchfinderError.ambiguous_candidate(self.name, hits)

    def __repr__(self) -> str:
        return f'MaskedInstructionPattern({self.name!r}, {len(self.values)} words)'


# ----------------------------------------------------------------------------------------------------------------
# Kernel profile registry
# ----------------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ResolverVariantProfile:
    signature: str
    payload: str
    support: str = 'supported'          # 'supported' | 'pending-research'


@dataclass(frozen=True)
class KernelResolverProfile:
    """Kernel identity (by embedded XNU fingerprint) and the resolver variants recovered for it. No offsets."""
    id: str
    product_version: str
    builds: Tuple[str, ...]
    boards: Tuple[str, ...]
    component: str
    embedded_fingerprint: str
    resolver_variants: Dict[str, ResolverVariantProfile] = field(default_factory=dict)
    omitted_resolvers: frozenset = frozenset()

    def __hash__(self) -> int:                  # resolver_variants is a dict; the id is unique per profile
        return hash(self.id)

    def covers(self, build: str) -> bool:
        return build in self.builds

    def variants(self, resolver: str) -> Optional[ResolverVariantProfile]:
        return self.resolver_variants.get(resolver)


TFP0_VARIANT_KEY = 'kernel-tfp0'
TFP0_SIGNATURE_ID = 'ios27-tfp0-v2'
TFP0_PAYLOAD_ID = 'task-for-pid-zero-slide-v3'
_TFP0_VARIANT = ResolverVariantProfile(TFP0_SIGNATURE_ID, TFP0_PAYLOAD_ID)


def _cm(signature: str) -> ResolverVariantProfile:
    return ResolverVariantProfile(signature, 'acm-return-success-v1')


# One XNU fingerprint can cover several Apple build IDs (24A435/24A437/24A446 share one) and several boards
# (24B119 n104ap and d421ap/d431ap ship different kernelcaches with the same XNU string).
KERNEL_RESOLVER_PROFILES: Tuple[KernelResolverProfile, ...] = (
    KernelResolverProfile(
        id='ios27-beta2-24A5370h-d421ap', product_version='27.0 beta 2', builds=('24A5370h',),
        boards=('d421ap', 'd431ap'), component='kernelcache.release.iphone12',
        embedded_fingerprint='xnu-13432.0.5.502.4~1/RELEASE_ARM64_T8030',
        resolver_variants={'kernel-credential-manager': _cm('ios27-early-beta-acm-v1')}),
    KernelResolverProfile(
        id='ios27-beta4-24A5390f-n104ap', product_version='27.0 beta 4', builds=('24A5390f',),
        boards=('n104ap',), component='kernelcache.release.iphone12b',
        embedded_fingerprint='xnu-13432.0.94.502.2~2/RELEASE_ARM64_T8030',
        resolver_variants={'kernel-credential-manager': _cm('ios27-early-beta-acm-v1')}),
    KernelResolverProfile(
        id='ios27-24A435-n104ap', product_version='27.0 RC/release, 27.0.1', builds=('24A435', '24A437', '24A446'),
        boards=('n104ap', 'd421ap', 'd431ap'), component='kernelcache.release.iphone12b',
        embedded_fingerprint='xnu-13432.2.10~2/RELEASE_ARM64_T8030',
        resolver_variants={'kernel-credential-manager': _cm('ios27-24A435-acm-v1'),
                           TFP0_VARIANT_KEY: _TFP0_VARIANT}),
    KernelResolverProfile(
        id='ios272-24B5084k-n104ap', product_version='27.2 beta 1', builds=('24B5084k',),
        boards=('n104ap',), component='kernelcache.release.iphone12b',
        embedded_fingerprint='xnu-13432.40.144.0.1~55/RELEASE_ARM64_T8030',
        resolver_variants={'kernel-credential-manager': _cm('ios272-24B5084k-acm-v1'),
                           TFP0_VARIANT_KEY: _TFP0_VARIANT}),
    KernelResolverProfile(
        id='ios272b2-24B5089g-n104ap', product_version='27.2 beta 2', builds=('24B5089g',),
        boards=('n104ap',), component='kernelcache.release.iphone12b',
        embedded_fingerprint='xnu-13432.40.162~93/RELEASE_ARM64_T8030',
        resolver_variants={'kernel-credential-manager': _cm('ios272b2-24B5089g-acm-v1'),
                           TFP0_VARIANT_KEY: _TFP0_VARIANT}),
    KernelResolverProfile(
        id='ios272b3-24B5099f-n104ap', product_version='27.2 beta 3', builds=('24B5099f',),
        boards=('n104ap',), component='kernelcache.release.iphone12b',
        embedded_fingerprint='xnu-13432.40.177.0.3~16/RELEASE_ARM64_T8030',
        resolver_variants={'kernel-credential-manager': _cm('ios272b3-24B5099f-acm-v1'),
                           TFP0_VARIANT_KEY: _TFP0_VARIANT}),
    KernelResolverProfile(
        id='ios272b4-24B5110a-n104ap', product_version='27.2 beta 4', builds=('24B5110a',),
        boards=('n104ap',), component='kernelcache.release.iphone12b',
        embedded_fingerprint='xnu-13432.42.3~13/RELEASE_ARM64_T8030',
        resolver_variants={'kernel-credential-manager': _cm('ios272b4-24B5110a-acm-v1'),
                           TFP0_VARIANT_KEY: _TFP0_VARIANT}),
    KernelResolverProfile(
        id='ios272-24B119-n104ap', product_version='27.2', builds=('24B119',),
        boards=('n104ap', 'd421ap', 'd431ap'), component='kernelcache.release.iphone12b',
        embedded_fingerprint='xnu-13432.42.3~28/RELEASE_ARM64_T8030',
        resolver_variants={'kernel-credential-manager': _cm('ios272-24B119-acm-v1'),
                           TFP0_VARIANT_KEY: _TFP0_VARIANT}),
)


def detect_kernel_profile(image: BinaryImage) -> Optional[KernelResolverProfile]:
    """The profile whose fingerprint occurs in the image, if exactly one does (unknown firmware -> None)."""
    def detect():
        matches = [p for p in KERNEL_RESOLVER_PROFILES if p.embedded_fingerprint.encode() in image.data]
        return matches[0] if len(matches) == 1 else None
    return image.memo(('detect_kernel_profile',), detect)


# ----------------------------------------------------------------------------------------------------------------
# Diagnostics
# ----------------------------------------------------------------------------------------------------------------

_CONDITIONS = ('eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv')


def describe_instruction(word: int, address: int) -> Tuple[str, str]:
    """(mnemonic, operands) for common control-flow and address-forming encodings; ('.word', hex) otherwise.

    Diagnostic only: this is not a disassembler, and resolvers must decide on raw encodings, never on this text.
    """
    def reg(n, wide=True, sp=False):
        if n == 31:
            return ('sp' if sp else 'xzr') if wide else ('wsp' if sp else 'wzr')
        return ('x%d' if wide else 'w%d') % n

    fixed = {0xD503_201F: 'nop', 0xD65F_03C0: 'ret', 0xD65F_0BFF: 'retaa', 0xD65F_0FFF: 'retab',
             0xD503_237F: 'pacibsp', 0xD503_245F: 'bti c', 0xD503_233F: 'paciasp'}
    if word in fixed:
        return fixed[word], ''
    target = ARM64.direct_branch_target(word, address)
    if target is not None:
        return ('bl' if word & 0x8000_0000 else 'b'), hex64(target)
    if word & 0xFF00_0010 == 0x5400_0000:
        return 'b.' + _CONDITIONS[word & 0xF], hex64(ARM64.conditional_target(word, address))
    if word & 0x7E00_0000 == 0x3400_0000:
        name = 'cbnz' if word & 0x0100_0000 else 'cbz'
        return name, f'{reg(word & 0x1F, bool(word >> 31))}, {hex64(ARM64.conditional_target(word, address))}'
    if word & 0x7E00_0000 == 0x3600_0000:
        name = 'tbnz' if word & 0x0100_0000 else 'tbz'
        bit = ((word >> 31) << 5) | ((word >> 19) & 0x1F)
        return name, f'{reg(word & 0x1F, bit >= 32)}, #{bit}, {hex64(ARM64.test_branch_target(word, address))}'
    if ARM64.is_adrp(word):
        return 'adrp', f'{reg(word & 0x1F)}, {hex64(ARM64.adrp_target(word, address))}'
    if word & 0x7F80_0000 == 0x1100_0000:
        wide = bool(word >> 31)
        return 'add', (f'{reg(word & 0x1F, wide, True)}, {reg((word >> 5) & 0x1F, wide, True)}, '
                       f'#{hex64(ARM64.add_immediate(word))}')
    if word & 0x7F80_0000 == 0x5280_0000:
        wide = bool(word >> 31)
        shift = ((word >> 21) & 3) * 16
        return 'movz', f'{reg(word & 0x1F, wide)}, #{hex64((word >> 5) & 0xFFFF)}' + (f', lsl #{shift}' if shift else '')
    if word & 0x7F80_0000 == 0x7280_0000:
        wide = bool(word >> 31)
        shift = ((word >> 21) & 3) * 16
        return 'movk', f'{reg(word & 0x1F, wide)}, #{hex64((word >> 5) & 0xFFFF)}' + (f', lsl #{shift}' if shift else '')
    if word & 0x3B00_0000 == 0x3900_0000:
        size = word >> 30
        load = (word >> 22) & 3
        name = ('str', 'ldr', 'ldrs', 'ldrs')[load] + ('b', 'h', '', '')[size]
        offset = ((word >> 10) & 0xFFF) << size
        dest = reg(word & 0x1F, size == 3 or load == 2)
        return name, f'{dest}, [{reg((word >> 5) & 0x1F, True, True)}, #{hex64(offset)}]'
    return '.word', hex32(word)


class BinaryInspector:
    """Read-only diagnostic queries using the same image, layout and ARM64 helpers as the resolvers."""

    def __init__(self, image: BinaryImage):
        self.image = image
        self.layout = MachOLayout.of(image)

    def segment_report(self) -> List[str]:
        return [f'{s.name:<18} vm {hex64(s.virtual_address)} file {hex64(s.file_offset)}..'
                f'{hex64(s.file_offset + s.file_size)} {"X" if s.is_executable else "-"}'
                for s in self.layout.segments]

    def string_occurrences(self, text: str, nul_terminated: bool = False) -> List[str]:
        lines = []
        for offset in self.image.find_all_utf8(text, nul_terminated):
            segment = self.layout.segment_containing(offset)
            lines.append(f'{hex64(offset)}  {segment.name if segment else "<unmapped>"}')
        return lines

    def references(self, to_file_offset: int) -> List[str]:
        lines = []
        for reference in self.layout.adrp_add_references(to_file_offset):
            owner = self.function_start(reference.adrp_offset)
            owner_text = f'in function {hex64(owner)}' if owner is not None else 'no enclosing prologue'
            lines.append(f'adrp {hex64(reference.adrp_offset)}  add {hex64(reference.add_offset)}  {owner_text}')
        return lines

    def function_start(self, offset: int, limit: int = 0x4000) -> Optional[int]:
        return ARM64.function_start(offset, self.image, self.layout, limit)

    def next_function_start(self, start: int, limit: int = 0x2000) -> int:
        return ARM64.next_function_start(start, self.image, self.layout, limit)

    def direct_call_targets(self, offset: int) -> List[int]:
        """Distinct BL destinations inside the function containing `offset` (file-offset arithmetic)."""
        start = self.function_start(offset)
        if start is None:
            return []
        end = self.next_function_start(start)
        targets = set()
        for cursor in range(start, end, 4):
            target = ARM64.branch_link_target(self.image.read_u32(cursor), cursor)
            if target is not None:
                targets.add(target)
        return sorted(targets)

    def objc_methods(self, selector: str, words: int = 2) -> List[str]:
        try:
            from . import objc as objc_module                     # imported as a package
        except ImportError:
            import objc as objc_module                            # flat import (package dir on sys.path)
        metadata = objc_module.ObjCMetadata(self.image)
        lines = []
        for method in metadata.methods(selector):
            encodings = ' '.join('%08x' % self.image.read_u32(method.implementation_offset + i * 4)
                                 for i in range(words))
            lines.append(f'imp {hex64(method.implementation_offset)}  va {hex64(method.implementation_address)}'
                         f'  entry {hex64(method.entry_offset)}  {encodings}')
        return lines

    def disassembly(self, offset: int, words: int) -> List[str]:
        lines = []
        for index in range(words):
            cursor = offset + index * 4
            word = self.image.read_u32(cursor)
            virtual = self.layout.virtual_address(cursor)
            mnemonic, operands = describe_instruction(word, cursor if virtual is None else virtual)
            lines.append(f'{hex64(cursor)}  {"-" if virtual is None else hex64(virtual)}  {word:08x}  '
                         f'{mnemonic:<10} {operands}')
        return lines

    def pattern_matches(self, values: Sequence[int], masks: Sequence[int]) -> List[int]:
        return MaskedInstructionPattern('inspect', values, masks).all_matches(
            self.image, self.layout.executable_file_ranges)

    def pattern_word_report(self, values: Sequence[int], masks: Sequence[int], offset: int) -> List[str]:
        lines = []
        for index, (value, mask) in enumerate(zip(values, masks)):
            cursor = offset + index * 4
            word = self.image.read_u32(cursor)
            lines.append(f'{"ok  " if word & mask == value else "DIFF"} {hex64(cursor)}  '
                         f'want {value:08x}/{mask:08x}  found {word:08x}')
        return lines


# ----------------------------------------------------------------------------------------------------------------
# Loading: IM4P / raw payloads
# ----------------------------------------------------------------------------------------------------------------

class _DER:
    """One DER element inside `data` (single-byte tags, definite lengths of at most 4 length bytes)."""

    __slots__ = ('data', 'start', 'value_start', 'end')

    def __init__(self, data: bytes, start: int, limit: int):
        if limit - start < 2:
            raise ValueError('truncated DER')
        first = data[start + 1]
        cursor = start + 2
        if first < 0x80:
            length = first
        elif first == 0x80:
            raise ValueError('indefinite DER length')
        else:
            count = first & 0x7F
            if count > 4 or limit - cursor < count:
                raise ValueError('truncated DER length')
            length = int.from_bytes(data[cursor:cursor + count], 'big')
            cursor += count
        if limit - cursor < length:
            raise ValueError('truncated DER value')
        self.data, self.start, self.value_start, self.end = data, start, cursor, cursor + length

    @property
    def tag(self) -> int:
        return self.data[self.start]

    @property
    def value(self) -> bytes:
        return self.data[self.value_start:self.end]

    def children(self) -> List['_DER']:
        result, cursor = [], self.value_start
        while cursor < self.end:
            child = _DER(self.data, cursor, self.end)
            result.append(child)
            cursor = child.end
        return result

    def string_value(self) -> str:
        return self.value.decode('utf-8')                         # strict: invalid UTF-8 raises

    def integer_value(self) -> int:
        result = 0
        for byte in self.value:
            result = ((result << 8) | byte) & MASK64
        return result


_LZSS_HEADER = 0x180


def _decompress_with_pyimg4(payload: bytes, size: int) -> bytes:
    try:
        from pyimg4 import Compression, IM4PData
    except ImportError as error:                                  # pragma: no cover - environment problem
        raise PatchfinderError.invalid_firmware_container(f'pyimg4 is required to decompress IM4P payloads: {error}')
    try:
        payload_data = IM4PData(payload, size=size)
        if payload_data.compression not in (Compression.LZSS, Compression.LZFSE):
            raise ValueError('payload is not an LZSS/LZFSE stream')
        payload_data.decompress()
        return payload_data.data
    except PatchfinderError:
        raise
    except Exception as error:  # noqa: BLE001 - pyimg4/apple_compress raise assorted types
        raise PatchfinderError.invalid_firmware_container(f'payload decompression failed: {error}')


class FirmwareArtifact:
    """A component payload and how it was wrapped: kind 'im4p' (decompressed IM4P payload) or 'raw'."""

    def __init__(self, kind: str, payload: bytes, fourcc: Optional[str] = None,
                 container_description: Optional[str] = None, compression: Optional[str] = None):
        self.kind = kind
        self.payload = payload
        self.fourcc = fourcc
        self.container_description = container_description
        self.compression = compression              # 'lzss' | 'lzfse' | None (as found in the container)

    @staticmethod
    def _im4p_children(data: bytes) -> Optional[List[_DER]]:
        """The IM4P's top-level children, or None when `data` is not an IM4P (then it is used raw)."""
        try:
            top = _DER(data, 0, len(data))
            if top.tag != 0x30:
                return None
            children = top.children()
            if len(children) < 4 or children[0].string_value() != 'IM4P':
                return None
            children[1].string_value()
            children[2].string_value()
            return children
        except (ValueError, IndexError, UnicodeDecodeError):
            return None

    @staticmethod
    def _lzfse_size(children: List[_DER]) -> Optional[int]:
        """Uncompressed size from a trailing SEQUENCE { INTEGER 1, INTEGER size } descriptor."""
        for child in children[4:]:
            if child.tag != 0x30:
                continue
            try:
                fields = child.children()
            except (ValueError, IndexError):
                continue
            if len(fields) < 2 or fields[0].integer_value() != 1:
                continue
            size = fields[1].integer_value()
            if size > 0:
                return size
        return None

    @classmethod
    def from_bytes(cls, data: bytes) -> 'FirmwareArtifact':
        children = cls._im4p_children(data)
        if children is None:
            return cls('raw', bytes(data))
        fourcc = children[1].string_value()
        description = children[2].string_value()
        payload = children[3].value
        if len(payload) > _LZSS_HEADER - 8 and payload.startswith(b'complzss'):
            size = int.from_bytes(payload[12:16], 'big')
            return cls('im4p', _decompress_with_pyimg4(payload, size)[:size], fourcc, description, 'lzss')
        size = cls._lzfse_size(children)
        if size is not None:
            output = _decompress_with_pyimg4(payload, size)[:size]
            if not output:
                raise PatchfinderError.invalid_firmware_container('LZFSE decompression failed')
            return cls('im4p', output, fourcc, description, 'lzfse')
        return cls('im4p', payload, fourcc, description, None)

    @classmethod
    def from_path(cls, path: str) -> 'FirmwareArtifact':
        with open(path, 'rb') as handle:
            return cls.from_bytes(handle.read())

    def require_im4p_fourcc(self, expected: str) -> None:
        if self.kind == 'im4p' and self.fourcc != expected:
            raise PatchfinderError.invalid_firmware_container(
                f'expected IM4P fourcc {expected}, found {self.fourcc or "unknown"}')


def load_image(path: str) -> BinaryImage:
    """Load an IM4P (decompressed payload) or a raw file as the BinaryImage whose offsets records use."""
    return BinaryImage(FirmwareArtifact.from_path(os.fspath(path)).payload)
