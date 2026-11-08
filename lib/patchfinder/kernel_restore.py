"""Kernel restore-plan resolver families: version-string identity, SSV/data-protection panics, AMFI policy
(including the kernel.debugger.* records it emits) and the profile-gated PPL trust-cache query.

Each public function takes a core.BinaryImage (the decompressed kernelcache) and returns [core.PatchRecord].
PREFIXES maps every function to the record-id prefixes it can emit (used by `resolve.py --only`).

    function                   what it patches                                          status
    identity                   both kernel version strings (RELEASE_ -> PATCHED_)       implemented
    panic                      the four SSV / data-protection panic branches            implemented
    amfi                       AMFI policy entry points, debugger and developer mode    implemented
    ppl_trust_cache            the PPL loaded-trust-cache result                        implemented
    ppl_trust_cache_required   ppl_trust_cache when the kernel profile opts in          implemented (profile gate)

Searches that conceptually test every executable word are done with indexed scans that return the same hits, in
the same order, as a word-by-word loop: core.BinaryImage.find_masked for fixed instruction shapes, a VA-band
restricted scan for conditional branches into a small window (_conditional_branches_into) and a lane-parallel BL
decoder for direct-call counts (_direct_call_counts). Each fast path re-checks every hit with the exact per-word
predicate.
"""
from __future__ import annotations

import functools
import struct
import sys
from array import array
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from . import core                     # imported as a package
except ImportError:                        # flat import: the package directory is on sys.path
    import core

PatchfinderError, PatchRecord = core.PatchfinderError, core.PatchRecord
ARM64, MachOLayout, hex64 = core.ARM64, core.MachOLayout, core.hex64
MASK32, MASK64 = core.MASK32, core.MASK64

COMPONENT = 'kernelcache'

PREFIXES = {
    'identity': ('kernel.identity.',),
    'panic': ('kernel.panic.',),
    'amfi': ('kernel.amfi.', 'kernel.debugger.'),
    'ppl_trust_cache': ('kernel.ppl.',),
    'ppl_trust_cache_required': ('kernel.ppl.',),
}

# ----------------------------------------------------------------------------------------------------------------
# identity: mark both kernel version strings
# ----------------------------------------------------------------------------------------------------------------

IDENTITY_PREFIX = '/RELEASE_ARM64_'
IDENTITY_PATCHED_PREFIX = '/PATCHED_ARM64_'
_MAX_PLATFORM_LENGTH = 16          # longest plausible SoC token after the prefix (T8030, T8020, T8101, ...)


def _platform_token(image: core.BinaryImage, prefix_offset: int) -> str:
    """The [A-Za-z0-9] SoC token after the prefix, stopping at the first other byte (the string's NUL)."""
    start = prefix_offset + len(IDENTITY_PREFIX.encode())
    available = min(_MAX_PLATFORM_LENGTH, max(0, image.count - start))
    token = bytearray()
    for byte in image.bytes_at(start, available):
        if 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A:
            token.append(byte)
        else:
            break
    if not token:
        raise PatchfinderError.missing_anchor(IDENTITY_PREFIX)
    return token.decode()


def identity(image: core.BinaryImage) -> List[PatchRecord]:
    """Rename `/RELEASE_ARM64_<SoC>` to `/PATCHED_ARM64_<SoC>` in both kernel version strings.

    Same length, so nothing moves; `uname` then proves the booted kernel is the patched artifact. Exactly two
    occurrences are required and both must carry the same SoC token, which is read from the binary.
    """
    sites = image.find_all_utf8(IDENTITY_PREFIX, nul_terminated=False)
    if len(sites) != 2:
        if not sites:
            raise PatchfinderError.missing_anchor(IDENTITY_PREFIX)
        raise PatchfinderError.ambiguous_anchor(IDENTITY_PREFIX, len(sites))

    platforms = [_platform_token(image, site) for site in sites]
    platform = platforms[0]
    if any(p != platform for p in platforms):
        raise PatchfinderError.no_candidate(
            'paired kernel version strings disagree on the SoC token: ' + ', '.join(platforms))

    original = (IDENTITY_PREFIX + platform).encode()
    replacement = (IDENTITY_PATCHED_PREFIX + platform).encode()
    return [
        PatchRecord(
            id=f'kernel.identity.{index}',
            component='kernelcache',
            offset=offset,
            original_bytes=original,
            replacement_bytes=replacement,
            summary=f'Mark kernel version string {index} ({platform}) as patched',
            evidence=(
                f'same-length RELEASE_ARM64_{platform} -> PATCHED_ARM64_{platform}',
                'exactly two occurrences in the kernelcache',
                'SoC token read from the binary',
                'no data moves, container layout unchanged',
            ),
        )
        for index, offset in enumerate(sorted(sites))
    ]


# ----------------------------------------------------------------------------------------------------------------
# Shared decoding helpers
# ----------------------------------------------------------------------------------------------------------------

def _word_patch(image: core.BinaryImage, id: str, offset: int, replacement: int, summary: str,  # noqa: A002
                evidence: Sequence[str]) -> PatchRecord:
    """One-instruction record whose original word is read from the image."""
    return PatchRecord.from_words(id=id, component=COMPONENT, offset=offset, original=image.read_u32(offset),
                                  replacement=replacement, summary=summary, evidence=evidence)


def _c_string_start(image: core.BinaryImage, offset: int) -> int:
    """The byte after the NUL that ends the previous C string; 0 when no NUL precedes `offset`.

    Code materialises the start of a C string, which is not necessarily where an anchor phrase begins."""
    return image.data.rfind(b'\0', 0, offset) + 1


def _in_executable(layout: MachOLayout, offset: int) -> bool:
    return any(offset in r for r in layout.executable_file_ranges)


def _function_start(image: core.BinaryImage, layout: MachOLayout, offset: int) -> int:
    """Nearest PACIBSP-led entry at or before `offset` (the BTI C pad when there is one); errors when the offset is
    not executable or no prologue is found within 0x4000 bytes."""
    if not _in_executable(layout, offset):
        raise PatchfinderError.no_candidate('containing executable range')
    start = ARM64.function_start(offset, image, layout)
    if start is None:
        raise PatchfinderError.no_candidate(f'arm64e function start before {hex64(offset)}')
    return start


def _direct_call_target(image: core.BinaryImage, layout: MachOLayout, offset: int) -> Optional[int]:
    """File offset a BL at `offset` calls (VA arithmetic), or None when it is no BL or either end is unmapped."""
    source = layout.virtual_address(offset)
    if source is None:
        return None
    target = ARM64.branch_link_target(image.read_u32(offset), source)
    if target is None:
        return None
    return layout.file_offset(target)


def _linear_pieces(layout: MachOLayout, r: range) -> List[Tuple[int, int, int]]:
    """Split the canonical word scan of executable range `r` (offsets (lo + 3) & ~3, +4, .. while offset + 4 <= hi)
    into pieces (first, stop, delta): every word offset in range(first, stop, 4) has virtual address offset + delta
    (the first segment containing it, as MachOLayout.virtual_address resolves it). Unmapped words are left out."""
    first = (r.start + 3) & ~3
    last = r.stop - 4                                   # highest word offset the scan reads
    if first > last:
        return []
    cuts = {first, last + 1}
    for segment in layout.segments:
        for bound in (segment.file_offset, segment.file_offset + segment.file_size):
            if first < bound <= last:
                cuts.add(bound)
    cuts = sorted(cuts)
    pieces = []
    for low, high in zip(cuts, cuts[1:]):
        start = first + ((low - first + 3) & ~3)        # first word offset of the scan inside [low, high)
        if start >= high:
            continue
        segment = layout.segment_containing(low)        # constant on [low, high): no segment bound inside
        if segment is None:
            continue
        pieces.append((start, high, segment.virtual_address - segment.file_offset))
    return pieces


def _mapped_back(layout: MachOLayout, target: int) -> List[int]:
    """Every virtual address that MachOLayout.file_offset maps to file offset `target`."""
    addresses = set()
    for segment in layout.segments:
        if target in segment.file_range:
            address = segment.virtual_address + (target - segment.file_offset)
            if layout.file_offset(address) == target:
                addresses.add(address)
    return sorted(addresses)


# Lane-parallel BL decoding. In a run of words at S, S + 4, .. whose virtual address is S + delta, a BL at lane i
# reaches virtual address v exactly when (imm26_i + i) mod 2^26 == ((v - S - delta) >> 2) mod 2^26 (v - S - delta
# divisible by 4). Adding the lane index to every low-26-bit field at once is one big-integer addition (no lane can
# carry into the next), after which every BL that reaches v in that run is the same 4-byte word and bytes.find
# locates them. Each hit is then re-decoded with _direct_call_target, so the count equals the per-word scan.

_BL_CHUNK_WORDS = 1 << 20
_LOW26_LANE = b'\xff\xff\xff\x03'
_U32 = struct.Struct('<I')
_U32_TYPECODE = 'I' if array('I').itemsize == 4 else 'L'


@functools.lru_cache(maxsize=4)
def _lane_constants(lanes: int) -> Tuple[int, int]:
    """(low-26-bit mask of every lane, lane index ramp 0, 1, .., lanes - 1) as little-endian big integers."""
    ramp = array(_U32_TYPECODE, range(lanes))
    if sys.byteorder != 'little':          # pragma: no cover - big-endian hosts
        ramp.byteswap()
    return int.from_bytes(_LOW26_LANE * lanes, 'little'), int.from_bytes(ramp.tobytes(), 'little')


def _direct_call_counts(image: core.BinaryImage, layout: MachOLayout, targets: Iterable[int]) -> Dict[int, int]:
    """For each target file offset: how many words in the executable ranges are BLs whose _direct_call_target is
    that offset (each range scanned with the canonical word loop, so overlapping ranges count twice, exactly as a
    per-word histogram would)."""
    counts = dict.fromkeys(targets, 0)
    wanted = [(address, target) for target in counts for address in _mapped_back(layout, target)]
    if not wanted:
        return counts
    data = image.data
    for r in layout.executable_file_ranges:
        for first, stop, delta in _linear_pieces(layout, r):
            for chunk in range(first, stop, 4 * _BL_CHUNK_WORDS):
                lanes = min(_BL_CHUNK_WORDS, (stop - chunk + 3) // 4)
                low, ramp = _lane_constants(lanes)
                words = int.from_bytes(data[chunk:chunk + 4 * lanes], 'little')
                folded = ((((words & low) + ramp) & low) | (words & ~low)).to_bytes(4 * lanes, 'little')
                for address, target in wanted:
                    distance = (address - chunk - delta) & MASK64
                    if distance & 3:
                        continue
                    needle = _U32.pack(0x9400_0000 | ((distance >> 2) & 0x03FF_FFFF))
                    hit = folded.find(needle)
                    while hit >= 0:
                        if hit & 3 == 0 and _direct_call_target(image, layout, chunk + hit) == target:
                            counts[target] += 1
                        hit = folded.find(needle, hit + 1)
    return counts


# Conditional branches have a short reach (signed imm19 or imm14 words), so only words whose virtual address lies
# within that distance of a target that maps into the window can branch into it. The classes are disjoint by
# encoding and together are exactly what ARM64.any_conditional_target decodes: (value, mask, reach in bytes).
_CONDITIONAL_CLASSES = (
    (0x3400_0000, 0x7E00_0000, 1 << 20),     # CBZ/CBNZ (W or X)
    (0x5400_0000, 0xFF00_0010, 1 << 20),     # B.cond
    (0x3600_0000, 0x7E00_0000, 1 << 15),     # TBZ/TBNZ
)


def _source_windows(layout: MachOLayout, r: range, bands: Sequence[Tuple[int, int]]) -> List[range]:
    """Merged sub-ranges of executable range `r` holding every scanned word whose virtual address can lie in one
    of the inclusive address `bands` (a superset: each segment's linear map is tried, first-match is not needed)."""
    last = r.stop - 4
    windows = []
    for segment in layout.segments:
        segment_last = segment.file_offset + segment.file_size - 1
        for low, high in bands:
            start = max(low - segment.virtual_address + segment.file_offset, segment.file_offset, r.start)
            end = min(high - segment.virtual_address + segment.file_offset, segment_last, last)
            if start <= end:
                windows.append((start, end + 4))
    windows.sort()
    merged: List[List[int]] = []
    for start, stop in windows:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], stop)
        else:
            merged.append([start, stop])
    return [range(start, stop) for start, stop in merged]


def _conditional_branches_into(image: core.BinaryImage, layout: MachOLayout, low: int,
                               high: int) -> List[Tuple[int, int]]:
    """(offset, target file offset) of every conditional branch in the executable ranges whose target maps to a
    file offset in [low, high]; range by range, ascending, as the word-by-word scan finds them."""
    targets = []                    # inclusive virtual-address intervals that can map back into [low, high]
    for segment in layout.segments:
        start, end = max(low, segment.file_offset), min(high, segment.file_offset + segment.file_size - 1)
        if start <= end:
            targets.append((segment.virtual_address + (start - segment.file_offset),
                            segment.virtual_address + (end - segment.file_offset)))
    read = image.read_u32
    branches = []
    for r in layout.executable_file_ranges:
        offsets = []
        for value, mask, reach in _CONDITIONAL_CLASSES:
            bands = [(first - reach, last + reach) for first, last in targets]
            wraps = any(band_low < 0 or band_high > MASK64 for band_low, band_high in bands)
            windows = [r] if wraps else _source_windows(layout, r, bands)
            offsets.extend(image.find_word(value, mask, windows))
        offsets.sort()
        for offset in offsets:
            source = layout.virtual_address(offset)
            if source is None:
                continue
            target = ARM64.any_conditional_target(read(offset), source)
            if target is None:
                continue
            target_offset = layout.file_offset(target)
            if target_offset is not None and low <= target_offset <= high:
                branches.append((offset, target_offset))
    return branches


# ----------------------------------------------------------------------------------------------------------------
# panic: skip the SSV / data-protection panic blocks
# ----------------------------------------------------------------------------------------------------------------

PANIC_ANCHORS: Tuple[Tuple[str, str], ...] = (
    ('root-snapshot', 'Failed to find the root snapshot'),
    ('seal-broken', 'root volume seal is broken'),
    ('rootvp-authentication', 'rootvp not authenticated after mounting'),
    ('unencrypted-data-volume', 'unencrypted data volume is not allowed'),
)
PANIC_BLOCK_WINDOW = 0x40


def panic(image: core.BinaryImage) -> List[PatchRecord]:
    """NOP the conditional branch entering each of the four SSV/data-protection panic blocks. Emits
    kernel.panic.{root-snapshot,seal-broken,rootvp-authentication,unencrypted-data-volume}.

    The shape that survives relinking is `conditional branch -> cold block: ADRP+ADD x0, format; BL panic`. Each
    phrase must occur once; its containing C string (the phrase may sit mid-string) must have exactly one ADRP+ADD
    reference. Among all conditional branches (CBZ/CBNZ/B.cond/TBZ/TBNZ) whose target lies in the 0x40 bytes up
    to and including that ADRP, the one whose target is closest to the ADRP must be unique.
    """
    layout = MachOLayout.of(image)
    records = []
    for anchor_id, text in PANIC_ANCHORS:
        substrings = image.find_all_utf8(text, nul_terminated=False)
        if len(substrings) != 1:
            if not substrings:
                raise PatchfinderError.missing_anchor(text)
            raise PatchfinderError.ambiguous_anchor(text, len(substrings))
        string_offset = _c_string_start(image, substrings[0])
        references = layout.adrp_add_references(string_offset)
        if len(references) != 1:
            if len(references) > 1:
                raise PatchfinderError.ambiguous_candidate(f'kernel panic xref: {text}',
                                                           [ref.adrp_offset for ref in references])
            raise PatchfinderError.no_candidate(f'kernel panic xref: {text}')
        adrp = references[0].adrp_offset

        target_floor = adrp - min(adrp, PANIC_BLOCK_WINDOW)
        branches = _conditional_branches_into(image, layout, target_floor, adrp)
        nearest = []
        if branches:
            nearest_gap = min(adrp - target for _, target in branches)
            nearest = [offset for offset, target in branches if adrp - target == nearest_gap]
        if len(nearest) != 1:
            if not nearest:
                raise PatchfinderError.no_candidate(f'kernel panic: {text}')
            raise PatchfinderError.ambiguous_candidate(f'kernel panic: {text}', nearest)
        records.append(_word_patch(
            image, f'kernel.panic.{anchor_id}', nearest[0], ARM64.nop,
            f'Do not enter the {anchor_id} panic block',
            (f'unique diagnostic phrase: {text}',
             'unique ADRP+ADD reference to its containing C string',
             'conditional target is uniquely closest to that xref within the 0x40-byte panic-block window')))
    return records


# ----------------------------------------------------------------------------------------------------------------
# amfi: AMFI policy entry points, PE_i_can_has_debugger and developer mode
# ----------------------------------------------------------------------------------------------------------------

_MOV_X20_X0 = 0xAA00_03F4


def amfi(image: core.BinaryImage) -> List[PatchRecord]:
    """AMFI trust-cache query, launch constraints, debugger and developer-mode checks, the post-validation compare
    and the dyld policy helpers, in that order. Emits kernel.amfi.{trust-cache.<0-4>,launch-constraints.*,
    developer-mode.*,post-validation.compare,dyld-policy.<0-1>} and kernel.debugger.{result,return}.

    Every site is an individual one-word record so the guarded applier checks each original word."""
    layout = MachOLayout.of(image)
    return (_amfi_trust_cache_stub(image, layout)
            + _amfi_launch_constraints_stub(image, layout)
            + _debugger_stub(image, layout)
            + _developer_mode_stub(image, layout)
            + [_amfi_post_validation_compare(image, layout)]
            + _amfi_dyld_policy_calls(image, layout))


def _string_references(image: core.BinaryImage, layout: MachOLayout, phrase: str) -> List[core.ADRPAddReference]:
    """ADRP+ADD references to the C string containing a phrase that must occur exactly once; at least one."""
    occurrences = image.find_all_utf8(phrase)
    if len(occurrences) != 1:
        if not occurrences:
            raise PatchfinderError.missing_anchor(phrase)
        raise PatchfinderError.ambiguous_anchor(phrase, len(occurrences))
    references = layout.adrp_add_references(_c_string_start(image, occurrences[0]))
    if not references:
        raise PatchfinderError.no_candidate(f'kernel xref: {phrase}')
    return references


def _unique_string_reference(image: core.BinaryImage, layout: MachOLayout, phrase: str) -> core.ADRPAddReference:
    references = _string_references(image, layout, phrase)
    if len(references) != 1:
        raise PatchfinderError.ambiguous_candidate(f'kernel xref: {phrase}', [r.adrp_offset for r in references])
    return references[0]


def _all_string_references(image: core.BinaryImage, layout: MachOLayout,
                           phrase: str) -> List[core.ADRPAddReference]:
    """References to every copy of a literal (a fileset can embed identical constants in several images); the code
    shape around each reference, not the first copy, has to disambiguate."""
    occurrences = image.find_all_utf8(phrase)
    if not occurrences:
        raise PatchfinderError.missing_anchor(phrase)
    references: List[core.ADRPAddReference] = []
    for start in sorted({_c_string_start(image, offset) for offset in occurrences}):
        references.extend(layout.adrp_add_references(start))
    if not references:
        raise PatchfinderError.no_candidate(f'kernel xref: {phrase}')
    return references


# -- AMFIIsCDHashInTrustCache --------------------------------------------------------------------------------------

def _trust_cache_shape(words: List[int], out_register: int) -> bool:
    """The trust-cache query's out-parameter data flow in the first 24 words of a PACIBSP function, for xN:
    MOV X19,xN (first such word, no PACIBSP before it), then STP XZR-pair zeroing, MOV xN,SP, BL, MOV X20,X0, and
    within the 7 words after that both CBNZ W0/X0 and CBZ X19."""
    try:
        save_index = words.index(0xAA00_03F3 | (out_register << 16))         # MOV X19,xN
    except ValueError:
        return False
    if ARM64.pacibsp in words[1:save_index]:     # a short wrapper must not borrow the next function's body
        return False
    count = len(words)

    def first(after: int, predicate) -> Optional[int]:
        return next((i for i in range(after + 1, count) if predicate(words[i])), None)

    zero_index = first(save_index, lambda w: w & 0xFFC0_7FFF == 0xA900_7FFF)
    if zero_index is None:
        return False
    pass_stack_slot = 0x9100_03E0 | out_register                                  # MOV xN,SP
    stack_index = first(zero_index, lambda w: w == pass_stack_slot)
    if stack_index is None:
        return False
    call_index = first(stack_index, lambda w: w & 0xFC00_0000 == 0x9400_0000)
    if call_index is None:
        return False
    result_index = first(call_index, lambda w: w == _MOV_X20_X0)
    if result_index is None:
        return False
    guards = range(result_index + 1, min(count, result_index + 8))
    return (any(words[i] & 0x7F00_001F == 0x3500_0000 for i in guards)          # CBNZ W0/X0
            and any(words[i] & 0xFF00_001F == 0xB400_0013 for i in guards))      # CBZ X19


def _amfi_trust_cache_stub(image: core.BinaryImage, layout: MachOLayout) -> List[PatchRecord]:
    """Locate AMFI's trust-cache query by its out-parameter data flow; the out-parameter register differs between
    builds (x2 / x3), so it is decoded from the body and reused by the stub."""
    hits: List[Tuple[int, int]] = []
    count = image.count
    for r in layout.executable_file_ranges:
        # every PACIBSP with start + 0x40 <= range end
        for start in image.find_word(ARM64.pacibsp, MASK32, (range(r.start, r.stop - 0x3C),)):
            if start + 24 * 4 <= count:
                words = image.u32[start >> 2:(start >> 2) + 24].tolist()
            else:
                words = [image.read_u32(start + i * 4) for i in range(24)]
            if _MOV_X20_X0 not in words:           # every match needs the result move; skip the rest cheaply
                continue
            registers = sorted({(w >> 16) & 0x1F for w in words if w & 0xFFE0_FFFF == 0xAA00_03F3} - {31})
            hits.extend((start, register) for register in registers if _trust_cache_shape(words, register))

    if len(hits) != 1:
        if not hits:
            raise PatchfinderError.no_candidate('AMFI trust-cache function')
        raise PatchfinderError.ambiguous_candidate('AMFI trust-cache function', [start for start, _ in hits])
    start, register = hits[0]
    replacements = (
        ARM64.bti_c,                        # BTI C
        ARM64.mov_x0_one,                   # MOV X0,#1
        0xB400_0040 | register,             # CBZ xN,+8
        0xF900_0000 | (register << 5),      # STR X0,[xN]
        ARM64.ret,                          # RET
    )
    return [_word_patch(image, f'kernel.amfi.trust-cache.{index}', start + index * 4, replacement,
                        f'Make AMFI trust-cache lookup succeed (word {index + 1}/5)',
                        (f'unique PACIBSP function with saved x{register} out-parameter',
                         'stack result is passed to a lookup call and followed by result/out-parameter guards'))
            for index, replacement in enumerate(replacements)]


# -- launch constraints --------------------------------------------------------------------------------------------

def _amfi_launch_constraints_stub(image: core.BinaryImage, layout: MachOLayout) -> List[PatchRecord]:
    reference = _unique_string_reference(image, layout, 'AMFI: Validation Category info')
    entry = _function_start(image, layout, reference.adrp_offset)
    # The function is reached through a taken address, so a BTI C landing pad must survive the stub.
    start = ARM64.stub_start(entry, image)
    return [
        _word_patch(image, 'kernel.amfi.launch-constraints.result', start, ARM64.mov_w0_zero,
                    'Return success from AMFI launch-constraint validation',
                    ('function uniquely owns the Validation Category diagnostic',)),
        _word_patch(image, 'kernel.amfi.launch-constraints.return', start + 4, ARM64.ret,
                    'Return immediately after the launch-constraint result',
                    ('paired entry-point stub',)),
    ]


# -- PE_i_can_has_debugger -----------------------------------------------------------------------------------------

def _is_debugger_leaf(image: core.BinaryImage, offset: int) -> bool:
    """ADRP X8 right after a RET*/PACIBSP boundary, CBZ X0 next, then LDR Wn,[X8,#imm] within words 1-8,
    STR Wn,[X0,#imm] within words 2-10 and a return within words 2-12."""
    read = image.read_u32
    previous = read(offset - 4)
    if read(offset) & 0x9F00_001F != 0x9000_0008:                      # ADRP X8,<page>
        return False
    if not (ARM64.is_return(previous) or previous == ARM64.pacibsp):
        return False
    if read(offset + 4) & 0xFF00_001F != 0xB400_0000:                  # CBZ X0,<target>
        return False
    has_load = any(read(offset + i * 4) & 0xFFC0_03E0 == 0xB940_0100 for i in range(1, 9))
    stores_through_output = any(read(offset + i * 4) & 0xFFC0_03E0 == 0xB900_0000 for i in range(2, 11))
    returns_locally = any(ARM64.is_return(read(offset + i * 4)) for i in range(2, 13))
    return has_load and stores_through_output and returns_locally


def _debugger_stub(image: core.BinaryImage, layout: MachOLayout) -> List[PatchRecord]:
    """PE_i_can_has_debugger has no stable string; it is the structurally valid ADRP X8 leaf with the optional x0
    output-pointer contract that has the most direct callers (call counts rank candidates, no fixed threshold)."""
    candidates: List[int] = []
    for r in layout.executable_file_ranges:
        first = max((r.start + 3) & ~3, r.start + 4)
        if first & 3:                         # unaligned walk (range starting 1 byte past alignment): word by word
            offsets: Iterable[int] = range(first, r.stop - 52 + 1, 4)
        else:                                 # ADRP X8 + CBZ X0 prefilter, offset + 52 <= range end
            offsets = image.find_masked((0x9000_0008, 0xB400_0000), (0x9F00_001F, 0xFF00_001F),
                                        (range(first, r.stop - 44),))
        candidates.extend(offset for offset in offsets if _is_debugger_leaf(image, offset))

    if not candidates:
        raise PatchfinderError.no_candidate('PE_i_can_has_debugger')
    call_counts = _direct_call_counts(image, layout, set(candidates))
    callers = [call_counts.get(offset, 0) for offset in candidates]
    maximum = max(callers)
    winners = [offset for offset, count in zip(candidates, callers) if count == maximum]
    if len(winners) != 1:
        raise PatchfinderError.ambiguous_candidate('PE_i_can_has_debugger', winners)
    start = winners[0]
    return [
        _word_patch(image, 'kernel.debugger.result', start, ARM64.mov_x0_one,
                    'Report that the platform permits a debugger',
                    ('unique highest-call-count ADRP x8 leaf with optional x0 output-pointer data flow',)),
        _word_patch(image, 'kernel.debugger.return', start + 4, ARM64.ret,
                    'Return the forced debugger result',
                    ('paired leaf-function stub',)),
    ]


# -- developer_mode_state ------------------------------------------------------------------------------------------

# ADRP X8 / LDR X8,[X8,#imm] / CBZ X8 / LDRB W8,[X8,#imm] / AND W0,W8,#1, then RET/RETAA/RETAB (checked per hit).
_DEVELOPER_MODE_VALUES = (0x9000_0008, 0xF940_0108, 0xB400_0008, 0x3940_0108, 0x1200_0100)
_DEVELOPER_MODE_MASKS = (0x9F00_001F, 0xFFC0_03FF, 0xFF00_001F, 0xFFC0_03FF, MASK32)


def _developer_mode_stub(image: core.BinaryImage, layout: MachOLayout) -> List[PatchRecord]:
    """developer_mode_state: follow a shared pointer, nil-check it, load one byte, keep bit zero, return."""
    hits = [offset for r in layout.executable_file_ranges
            for offset in image.find_masked(_DEVELOPER_MODE_VALUES, _DEVELOPER_MODE_MASKS,
                                            (range(r.start, r.stop - 4),))      # offset + 24 <= range end
            if ARM64.is_return(image.read_u32(offset + 20))]
    if len(hits) != 1:
        if not hits:
            raise PatchfinderError.no_candidate('developer_mode_state')
        raise PatchfinderError.ambiguous_candidate('developer_mode_state', hits)
    start = hits[0]
    return [
        _word_patch(image, 'kernel.amfi.developer-mode.result', start, ARM64.mov_w0_one,
                    'Report developer mode enabled',
                    ('unique shared-pointer byte accessor masked to bit zero',)),
        _word_patch(image, 'kernel.amfi.developer-mode.return', start + 4, ARM64.ret,
                    'Return the forced developer-mode result',
                    ('paired accessor stub',)),
    ]


# -- post-validation compare ---------------------------------------------------------------------------------------

def _amfi_post_validation_compare(image: core.BinaryImage, layout: MachOLayout) -> PatchRecord:
    """In a callee of the function(s) owning the code-signature validation diagnostic: the unique CMP W0,#imm that
    follows a BL (one or two words earlier) and is consumed by B.NE."""
    callers = set()
    callees = set()
    for reference in _string_references(image, layout, 'AMFI: code signature validation failed'):
        caller_start = _function_start(image, layout, reference.adrp_offset)
        if caller_start in callers:
            continue
        callers.add(caller_start)
        caller_end = ARM64.next_function_start(caller_start, image, layout, 0x2000)
        for offset in range(caller_start, caller_end, 4):
            target = _direct_call_target(image, layout, offset)
            if target is not None:
                callees.add(target)

    read = image.read_u32
    hits = set()
    for callee in callees:
        if not _in_executable(layout, callee):
            continue
        end = ARM64.next_function_start(callee, image, layout, 0x200)
        for cursor in range(callee + 8, end - 4, 4):                # while cursor + 4 < end
            if (read(cursor) & 0x7F00_03FF == 0x7100_001F                      # CMP W0,#imm (SUBS WZR,W0,#imm)
                    and read(cursor + 4) & 0xFF00_001F == 0x5400_0001          # B.NE
                    and any(_direct_call_target(image, layout, site) is not None
                            for site in (cursor - 4, cursor - 8))):
                hits.add(cursor)
    unique_hits = sorted(hits)
    if len(unique_hits) != 1:
        if not unique_hits:
            raise PatchfinderError.no_candidate('AMFI postValidation compare')
        raise PatchfinderError.ambiguous_candidate('AMFI postValidation compare', unique_hits)
    site = unique_hits[0]
    # Which way the B.NE must go is a property of the build: when the fallthrough is the reject path the compare
    # must come out unequal, otherwise equal. Decide from the fallthrough code, never from the build number.
    rejects_on_fallthrough = fallthrough_builds_diagnostic(image, site + 4)
    replacement = post_validation_replacement(read(site), rejects_on_fallthrough)
    summary = ('Force the post-validation comparison unequal so the accept branch is taken'
               if rejects_on_fallthrough else 'Make the post-validation comparison equal')
    return _word_patch(
        image, 'kernel.amfi.post-validation.compare', site, replacement, summary,
        ('callee of the function owning the code-signature validation diagnostic',
         'CMP W0,#imm follows a BL and is immediately consumed by B.NE',
         'fallthrough formats a diagnostic and branches to the shared reject tail' if rejects_on_fallthrough
         else 'fallthrough continues into the function body'))


def post_validation_replacement(compare: int, rejects_on_fallthrough: bool) -> int:
    """Replacement for the post-validation CMP W0,#imm. When the fallthrough rejects, B.NE is the accept edge and
    must always be taken: CMP WZR,#imm (never equal for a non-zero immediate; a zero immediate is an error).
    Otherwise the fallthrough accepts and B.NE must never be taken: CMP W0,W0 (always equal)."""
    if not rejects_on_fallthrough:
        return 0x6B00_001F                                              # CMP W0,W0: Z always set
    if (compare >> 10) & 0xFFF == 0:
        raise PatchfinderError.no_candidate(
            'AMFI postValidation compare with a zero immediate cannot be forced unequal')
    return ((compare & ~0x3E0) | (31 << 5)) & MASK32                   # Rn := WZR, result -imm, Z clear


def fallthrough_builds_diagnostic(image: core.BinaryImage, branch: int) -> bool:
    """True when the six words after a conditional branch form a reject block: an ADRP (diagnostic format string)
    followed by an unconditional B to the shared logging tail. The accept path starts an authenticated dispatch."""
    saw_adrp = False
    for index in range(1, 7):
        offset = branch + index * 4
        if offset + 4 > image.count:
            return False
        word = image.read_u32(offset)
        if word & 0x9F00_0000 == 0x9000_0000:
            saw_adrp = True
        if saw_adrp and word & 0xFC00_0000 == 0x1400_0000:
            return True
    return False


# -- dyld policy ---------------------------------------------------------------------------------------------------

def _amfi_dyld_policy_calls(image: core.BinaryImage, layout: MachOLayout) -> List[PatchRecord]:
    """The two helper calls before the development-build entitlement check: walking back up to 80 bytes from each
    reference, the two nearest BLs immediately tested by CBZ/CBNZ/TBZ/TBNZ on register 0 must call different
    functions; exactly one such pair of sites must exist over all references."""
    read = image.read_u32
    candidates: List[List[int]] = []
    for reference in _all_string_references(
            image, layout, 'com.apple.developer.swift-playgrounds-app.development-build'):
        lower = reference.adrp_offset - min(reference.adrp_offset, 80)
        pairs: List[Tuple[int, int]] = []
        cursor = reference.adrp_offset
        while cursor >= lower + 4:
            cursor -= 4
            target = _direct_call_target(image, layout, cursor)
            if target is None:
                continue
            following = read(cursor + 4)
            is_compare_branch = following & 0x7E00_0000 == 0x3400_0000           # CBZ/CBNZ
            is_test_branch = following & 0x7E00_0000 == 0x3600_0000              # TBZ/TBNZ
            if (is_compare_branch or is_test_branch) and following & 0x1F == 0:
                pairs.append((cursor, target))
        if len(pairs) < 2 or pairs[0][1] == pairs[1][1]:
            continue
        sites = sorted((pairs[1][0], pairs[0][0]))
        if sites not in candidates:
            candidates.append(sites)
    if len(candidates) != 1:
        if not candidates:
            raise PatchfinderError.no_candidate('dyld policy helper-call pair')
        raise PatchfinderError.ambiguous_candidate('dyld policy helper-call pair',
                                                   [site for sites in candidates for site in sites])
    return [_word_patch(image, f'kernel.amfi.dyld-policy.{index}', site, ARM64.mov_w0_one,
                        f'Make dyld policy helper {index + 1} succeed',
                        ('within 80 bytes of the Swift Playgrounds development entitlement xref',
                         'BL is immediately followed by a conditional test of w0 and the two helpers differ'))
            for index, site in enumerate(candidates[0])]


# ----------------------------------------------------------------------------------------------------------------
# ppl_trust_cache: profile-gated PPL loaded-trust-cache result
# ----------------------------------------------------------------------------------------------------------------

PPL_TRUST_CACHE_VARIANT_KEY = 'kernel-ppl-trust-cache'
PPL_TRUST_CACHE_SIGNATURE_ID = 't8020-loaded-trust-cache-v1'
PPL_TRUST_CACHE_PAYLOAD_ID = 'loaded-trust-cache-true-v1'

# Copy the 20 CDHash bytes to a stack buffer, query loadable trust caches (type 2), turn KERN_SUCCESS into a
# boolean (CSET W0,EQ at word 17); stack canary, authenticated frame and RETAB stay intact.
PPL_TRUST_CACHE_PATTERN = core.MaskedInstructionPattern.from_reference_words('PPL loaded trust-cache helper', (
    0xD503_237F, 0xD100_C3FF, 0xA902_7BFD, 0x9100_83FD,
    0x9000_0008, 0x9100_0108, 0xF940_0108, 0xF81F_83A8,
    0x3DC0_0000, 0x3D80_03E0, 0xB940_1008, 0xB900_13E8,
    0x9100_03E1, 0x5280_0040, 0xD280_0002, 0x9400_0000,
    0x7100_001F, 0x1A9F_17E0,
    0xF85F_83A8, 0x9000_0009, 0x9100_0129, 0xF940_0129,
    0xEB08_013F, 0x5400_0081, 0xA942_7BFD, 0x9100_C3FF, 0xD65F_0FFF,
))
_PPL_RESULT_WORD_INDEX = 17

# Direct caller: BL helper / TBZ W0,#0,+12 / MOV W8,#9 (loaded trust cache trust level) / B.
_PPL_CALLER_VALUES = (0x9400_0000, 0x3600_0060, 0x5280_0128, 0x1400_0000)
_PPL_CALLER_MASKS = (0xFC00_0000, MASK32, MASK32, 0xFC00_0000)


def ppl_trust_cache(image: core.BinaryImage) -> List[PatchRecord]:
    """Make the PPL loaded-trust-cache helper report success: its CSET W0,EQ becomes MOV W0,#1. Emits
    kernel.ppl.loaded-trust-cache-result.

    T8020-class PPL enforces executable trust on its own, so the AMFI query stub alone does not give an ad-hoc
    binary a PPL code-signing trust level. Requires the detected kernel profile's 'kernel-ppl-trust-cache' variant
    to be supported with signature 't8020-loaded-trust-cache-v1' / payload 'loaded-trust-cache-true-v1', the
    helper to match its complete signature uniquely and exactly one direct caller to map true to trust level 9.
    """
    profile = core.detect_kernel_profile(image)
    variant = profile.variants(PPL_TRUST_CACHE_VARIANT_KEY) if profile is not None else None
    if (variant is None or variant.support != 'supported'
            or variant.signature != PPL_TRUST_CACHE_SIGNATURE_ID or variant.payload != PPL_TRUST_CACHE_PAYLOAD_ID):
        raise PatchfinderError.unsupported_firmware_profile(
            PPL_TRUST_CACHE_VARIANT_KEY, profile.id if profile is not None else 'unidentified', 'unregistered')
    layout = MachOLayout.of(image)
    entry = PPL_TRUST_CACHE_PATTERN.unique_match(image, layout)
    entry_address = layout.virtual_address(entry)
    if entry_address is None:
        raise PatchfinderError.no_candidate('mapped PPL trust-cache entry')

    read = image.read_u32
    callers = []
    for r in layout.executable_file_ranges:
        for offset in image.find_masked(_PPL_CALLER_VALUES, _PPL_CALLER_MASKS, (r,)):
            address = layout.virtual_address(offset)
            if address is not None and ARM64.branch_link_target(read(offset), address) == entry_address:
                callers.append(offset)
    if len(callers) != 1:
        raise PatchfinderError.ambiguous_candidate('PPL trust-level-9 caller', callers)

    offset = entry + _PPL_RESULT_WORD_INDEX * 4
    return [_word_patch(
        image, 'kernel.ppl.loaded-trust-cache-result', offset, ARM64.mov_w0_one,
        'Accept the loaded trust-cache decision in T8020 PPL',
        ('unique complete CDHash-copy/type-2-query/stack-canary function',
         'unique direct caller maps true to trust level 9',
         'only CSET W0,EQ changes; query, frame and RETAB remain intact'))]


def ppl_trust_cache_required(image: core.BinaryImage) -> List[PatchRecord]:
    """The restore plan's PPL step: nothing unless the detected kernel profile opts in to the PPL variant."""
    profile = core.detect_kernel_profile(image)
    if profile is None or profile.variants(PPL_TRUST_CACHE_VARIANT_KEY) is None:
        return []
    return ppl_trust_cache(image)
