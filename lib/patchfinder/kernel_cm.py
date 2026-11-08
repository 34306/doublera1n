"""Kernel boot-plan resolver families for the SEP credential manager and the Valeria registration repair.

Each public function takes a core.BinaryImage (the decompressed kernelcache) and returns [core.PatchRecord].
PREFIXES maps every record-emitting function to the record-id prefixes it can emit (used by `resolve.py --only`).

    function                    what it does                                                  status
    credential_manager          AppleSEPCredentialManager methods return success              implemented
    credential_manager_probe    diagnostic: how well a recorded family matches (no records)   implemented
    valeria                     Valeria class-command registration repair                     implemented
    valeria_composite           valeria, unless the kernel profile omits it                   implemented (profile gate)

The credential-manager signature/payload variant comes from core.detect_kernel_profile(image)
.variants('kernel-credential-manager'); a missing or unsupported variant is
PatchfinderError.unsupported_firmware_profile, and an unidentified kernel tries every supported family (see
_credential_manager_unknown_kernel). The recorded method shapes live in kernel_cm_signatures.
"""
from __future__ import annotations

import functools
import re
import struct
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

try:
    from . import core                     # imported as a package
    from . import kernel_cm_signatures as signatures_data
except ImportError:                        # flat import: the package directory is on sys.path
    import core
    import kernel_cm_signatures as signatures_data

PatchfinderError, PatchRecord = core.PatchfinderError, core.PatchRecord
ARM64, MaskedInstructionPattern = core.ARM64, core.MaskedInstructionPattern

CREDENTIAL_MANAGER_NAME = 'kernel-credential-manager'
VALERIA_NAME = 'kernel-valeria'
COMPONENT = 'kernelcache'

PREFIXES = {
    'credential_manager': ('kernel.credential-manager.',),
    'valeria': ('kernel.valeria.',),
    'valeria_composite': ('kernel.valeria.',),
}


# ================================================================================================================
# Credential manager: every AppleSEPCredentialManager method of the profile's family returns success
# ================================================================================================================
#
# The detected profile names a signature family (kernel_cm_signatures.VARIANTS) and a payload. Methods with a unique
# relocation-masked body are matched exactly; a method marked needs_scoring is ranked by 32-word similarity among
# the genuine entries (PACIBSP or BTI C) strictly between its resolved neighbours. The resolved entries must
# increase in class order. Each method then becomes `mov w0, #0; ret`, written after any BTI C landing pad.

class CredentialManagerSignature(NamedTuple):
    """One recorded method shape: record id stem, method name, masked pattern, located by scoring or exactly."""
    id: str
    name: str
    pattern: MaskedInstructionPattern
    needs_scoring: bool


class CredentialManagerPayload(NamedTuple):
    id: str
    result: int                 # first stub word (the forced return value)
    return_instruction: int     # second stub word


CREDENTIAL_MANAGER_PAYLOADS: Dict[str, CredentialManagerPayload] = {
    'acm-return-success-v1': CredentialManagerPayload('acm-return-success-v1', ARM64.mov_w0_zero, ARM64.ret),
}

# Integer ranking rules for needs_scoring methods: at least this many of the 32 masked words must agree, and the
# best entry must lead the runner-up by at least the margin.
SCORE_MINIMUM_MATCHES = 23
SCORE_MINIMUM_LEAD = 5


_HEX_TOKEN = re.compile(r'[0-9A-Fa-f]+')


def _signature_id(name: str) -> str:
    """Record id stem: surrounding underscores trimmed, '_' and ' ' -> '-', lowercased."""
    return name.strip('_').replace('_', '-').replace(' ', '-').lower()


def _reference_words(text: str) -> List[int]:
    """Parse whitespace-separated hex instruction words (a malformed table entry is a programming error)."""
    words = []
    for token in text.split():
        if not _HEX_TOKEN.fullmatch(token) or int(token, 16) > core.MASK32:
            raise ValueError(f'invalid reference instruction: {token}')
        words.append(int(token, 16))
    return words


def _build_signature(entry: 'signatures_data.Signature') -> CredentialManagerSignature:
    pattern = MaskedInstructionPattern.from_reference_words(
        f'AppleCredentialManager::{entry.name}', _reference_words(entry.words), allow_data_layout_drift=True)
    return CredentialManagerSignature(_signature_id(entry.name), entry.name, pattern, bool(entry.needs_scoring))


# Built at import so a malformed table fails immediately rather than on the first matching kernel.
CREDENTIAL_MANAGER_SIGNATURES: Dict[str, Tuple[CredentialManagerSignature, ...]] = {
    variant_id: tuple(_build_signature(entry) for entry in entries)
    for variant_id, entries in signatures_data.VARIANTS.items()
}


def credential_manager_signatures(variant_id: str) -> Optional[Tuple[CredentialManagerSignature, ...]]:
    """The recorded family named `variant_id`, or None."""
    return CREDENTIAL_MANAGER_SIGNATURES.get(variant_id)


def credential_manager(image: core.BinaryImage) -> List[PatchRecord]:
    """Make each AppleSEPCredentialManager method in the profile's signature family return success without
    running its body (two records per method: .result and .return). Emits kernel.credential-manager.*."""
    profile = core.detect_kernel_profile(image)
    if profile is None:
        return _credential_manager_unknown_kernel(image)
    selected = profile.variants(CREDENTIAL_MANAGER_NAME)
    if selected is None:
        raise PatchfinderError.unsupported_firmware_profile(CREDENTIAL_MANAGER_NAME, profile.id, 'unregistered')
    functions = credential_manager_signatures(selected.signature)
    payload = CREDENTIAL_MANAGER_PAYLOADS.get(selected.payload)
    if selected.support != 'supported' or functions is None or payload is None:
        raise PatchfinderError.unsupported_firmware_profile(CREDENTIAL_MANAGER_NAME, profile.id, selected.signature)
    return _resolve_with(functions, payload, image, ())


def _credential_manager_unknown_kernel(image: core.BinaryImage) -> List[PatchRecord]:
    """A kernel whose XNU fingerprint is not registered (a newer build): try every supported signature family,
    newest kernel first, and take the first one under which ALL methods resolve with the normal rules (unique
    relocation-masked bodies, neighbour-bounded scoring with its minimum and lead, class order). A family that
    fails any method is rejected as a whole, so nothing is patched from a partial match."""
    tried, failures = set(), []
    for known in reversed(core.KERNEL_RESOLVER_PROFILES):
        variant = known.variants(CREDENTIAL_MANAGER_NAME)
        if variant is None or variant.support != 'supported' or variant.signature in tried:
            continue
        tried.add(variant.signature)
        functions = credential_manager_signatures(variant.signature)
        payload = CREDENTIAL_MANAGER_PAYLOADS.get(variant.payload)
        if functions is None or payload is None:
            continue
        try:
            return _resolve_with(functions, payload, image,
                                 (f'unregistered kernel: signature family {variant.signature} '
                                  f'(nearest match, from {known.product_version})',))
        except PatchfinderError as e:
            failures.append(f'{variant.signature}: {e}')
    raise PatchfinderError.unsupported_firmware_profile(
        CREDENTIAL_MANAGER_NAME, 'unidentified', 'no known signature family resolves every method')


def _resolve_with(functions, payload, image: core.BinaryImage, extra_evidence: Tuple[str, ...]) -> List[PatchRecord]:
    layout = core.MachOLayout.of(image)
    resolved: Dict[int, int] = {}

    # Strict signatures first: they are evidence in their own right and the ordering rails for scored methods.
    for index, descriptor in enumerate(functions):
        if not descriptor.needs_scoring:
            resolved[index] = descriptor.pattern.unique_match(image, layout)

    for index, descriptor in enumerate(functions):
        if descriptor.needs_scoring:
            resolved[index] = _scored_function_entry(descriptor, resolved.get(index - 1), resolved.get(index + 1),
                                                     image, layout)

    ordered = []
    for index, descriptor in enumerate(functions):
        offset = resolved.get(index)
        if offset is None:
            raise PatchfinderError.no_candidate(descriptor.name)
        ordered.append(offset)
    if not all(a < b for a, b in zip(ordered, ordered[1:])):
        raise PatchfinderError.invalid_fixture('AppleCredentialManager functions did not resolve in reference order')

    records: List[PatchRecord] = []
    for descriptor, entry in zip(functions, ordered):
        method = ('neighbor-bounded 32-word similarity' if descriptor.needs_scoring
                  else 'unique relocation-masked function body')
        # Several methods are reached only through a taken address, so the stub goes after a BTI C landing pad
        # rather than on top of it.
        start = ARM64.stub_start(entry, image)
        records.append(_kernel_word_patch(
            image, f'kernel.credential-manager.{descriptor.id}.result', start, payload.result,
            f'Return success from {descriptor.name}',
            (method, 'genuine PACIBSP or BTI C function entry') + extra_evidence))
        records.append(_kernel_word_patch(
            image, f'kernel.credential-manager.{descriptor.id}.return', start + 4, payload.return_instruction,
            'Return the forced AppleCredentialManager result',
            ('paired entry-point stub',)))
    return records


def _scored_function_entry(descriptor: CredentialManagerSignature, lower_neighbor: Optional[int],
                           upper_neighbor: Optional[int], image: core.BinaryImage, layout: core.MachOLayout) -> int:
    """Rank genuine arm64e entries (PACIBSP or BTI C) strictly after the lower neighbour and before the upper one
    (or the end of each executable range when that neighbour is unresolved) by masked-word agreement."""
    if lower_neighbor is None:
        raise PatchfinderError.no_candidate(f'lower neighbor for {descriptor.name}')
    pattern = descriptor.pattern
    signature_bytes = len(pattern.values) * 4
    scores: List[Tuple[int, int]] = []          # (matching words, offset)

    for r in layout.executable_file_ranges:
        lower = max(r.start, lower_neighbor + 4)
        upper = min(r.stop, r.stop if upper_neighbor is None else upper_neighbor)
        if not (upper > lower and upper - lower >= signature_bytes):
            continue
        # Offsets o = (lower + 3) & ~3, +4, ... with o + signature_bytes <= upper.
        window = range(lower, upper - signature_bytes + 4)
        entries = _word_offsets(image, ARM64.pacibsp, window) + _word_offsets(image, ARM64.bti_c, window)
        scores.extend((_matching_word_count(pattern, image, offset), offset) for offset in entries)

    scores.sort(key=lambda item: (-item[0], item[1]))
    if not scores or scores[0][0] < SCORE_MINIMUM_MATCHES:
        best = scores[0][0] if scores else 0
        raise PatchfinderError.no_candidate(f'{descriptor.name} similarity entry (best {best}/32)')
    if len(scores) > 1 and scores[0][0] - scores[1][0] < SCORE_MINIMUM_LEAD:
        raise PatchfinderError.ambiguous_candidate(f'{descriptor.name} similarity entry',
                                                   [offset for _, offset in scores[:5]])
    return scores[0][1]


def _word_offsets(image: core.BinaryImage, word: int, r: range) -> List[int]:
    """image.find_word(word, ranges=(r,)) for a fully specified word, via bytes.find (an open-ended scoring window
    holds 100k+ function entries, where a regex search per hit is slow)."""
    data = image.data
    needle = struct.pack('<I', word)
    stop = min(r.stop, len(data))
    offsets = []
    position = data.find(needle, (r.start + 3) & ~3, stop)
    while position != -1:
        if position & 3 == 0:
            offsets.append(position)
        position = data.find(needle, position + 1, stop)
    return offsets


@functools.lru_cache(maxsize=None)
def _lane_constants(values: Tuple[int, ...], masks: Tuple[int, ...]) -> Tuple[int, int, int, int]:
    """(masks, values, 0x7fffffff per lane, 0x80000000 per lane) as little-endian integers, word i in bits 32i+."""
    count = len(values)
    return (int.from_bytes(struct.pack(f'<{count}I', *masks), 'little'),
            int.from_bytes(struct.pack(f'<{count}I', *values), 'little'),
            int.from_bytes(b'\xff\xff\xff\x7f' * count, 'little'),
            int.from_bytes(b'\x00\x00\x00\x80' * count, 'little'))


def _popcount(value: int) -> int:
    return value.bit_count() if hasattr(value, 'bit_count') else bin(value).count('1')


def _matching_word_count(pattern: MaskedInstructionPattern, image: core.BinaryImage, offset: int) -> int:
    """pattern.matching_word_count(image, offset), computed on whole-pattern big integers.

    An open-ended scoring window can hold 100k+ candidate entries. x = (bytes & masks) ^ values has a zero 32-bit
    lane exactly where a word matches; ((x & 0x7fffffff..) + 0x7fffffff..) | x sets a lane's top bit exactly when
    the lane is non-zero, without carrying into the next lane.
    """
    count = len(pattern.values)
    if offset < 0 or offset + 4 * count > image.count:
        return pattern.matching_word_count(image, offset)          # per-word path: raises out_of_bounds
    masks, values, low31, high = _lane_constants(pattern.values, pattern.masks)
    x = (int.from_bytes(image.data[offset:offset + 4 * count], 'little') & masks) ^ values
    return count - _popcount((((x & low31) + low31) | x) & high)


# ----------------------------------------------------------------------------------------------------------------
# Credential-manager probe (diagnostic): how a recorded family fares against an arbitrary kernelcache
# ----------------------------------------------------------------------------------------------------------------

class CredentialManagerFunctionReport(NamedTuple):
    name: str
    recorded_words: int         # words in the recorded signature
    matched_words: int          # longest tried leading prefix that still matches somewhere (0: none)
    offsets: Tuple[int, ...]    # where that prefix matched (at most 33, in range order)

    @property
    def is_exact(self) -> bool:
        """Usable as-is: the complete recorded shape occurs exactly once."""
        return self.matched_words == self.recorded_words and len(self.offsets) == 1


# Prefix lengths tried when the full signature fails, longest first. A shorter prefix is not a locator; it tells a
# rewritten method apart from an intact one in which a later instruction moved.
_PROBE_PREFIX_FRACTIONS = (1.0, 0.75, 0.5, 0.375, 0.25)
_PROBE_MAXIMUM_HITS = 33        # matching stops once more than 32 hits are known


def credential_manager_probe(image: core.BinaryImage, variant_id: str) -> List[CredentialManagerFunctionReport]:
    """Probe every method of the recorded family `variant_id` against `image`, in recorded order. For each, the
    longest of the tried prefixes (100/75/50/37.5/25 %, at least 4 words) that matches anywhere is reported with
    its hits; an ambiguous prefix is still a finding. Emits no patch records."""
    functions = credential_manager_signatures(variant_id)
    if functions is None:
        raise PatchfinderError.invalid_fixture(f'unknown ACM signature variant: {variant_id}')
    layout = core.MachOLayout.of(image)
    reports = []
    for descriptor in functions:
        pattern = descriptor.pattern
        total = len(pattern.values)
        report = CredentialManagerFunctionReport(descriptor.name, total, 0, ())
        for fraction in _PROBE_PREFIX_FRACTIONS:
            count = max(4, int(total * fraction))
            if count > total:
                continue
            prefix = MaskedInstructionPattern(pattern.name, pattern.values[:count], pattern.masks[:count])
            hits = prefix.all_matches(image, layout.executable_file_ranges)[:_PROBE_MAXIMUM_HITS]
            if hits:
                report = CredentialManagerFunctionReport(descriptor.name, total, count, tuple(hits))
                break
        reports.append(report)
    return reports


# ================================================================================================================
# Valeria: reclaim an inactive class-command callback owner at selector-8 registration
# ================================================================================================================
#
# After a forced USB re-enumeration the old user client can stay retained as the provider's callback owner (+0xd0),
# so the replacement client's selector-8 call reaches the class-command registration action and gets
# kIOReturnBusy. That action runs on the provider command gate, the first race-safe point that sees both clients.
# The owner load there becomes a BL to a shim in verified executable padding: a null or live owner behaves as
# stock; an owner whose IOService state word (+0x48) has kIOServiceInactiveState (bit 0) set is released through
# the provider's own direct-clear routine, and control resumes on the stock null-owner path.

# Selector 8's +0x5c0 command-gate action. Its tail stores X20 in the second callback slot, which makes this owner
# check unique next to the message-callback action. PAC discriminator immediates may drift between collections.
VALERIA_OWNER_CHECK = MaskedInstructionPattern(
    'IOUSBDeviceInterface class-command callback owner check',
    (0xF940_6A68, 0xB400_0008, 0x1100_4C00, 0x1400_0000,
     0xF900_6A61, 0xF940_0030, 0xAA01_03F1, 0xF2E0_0011,
     0xDAC1_1A30, 0xF842_0E08, 0xAA01_03E0, 0xF2E0_0010,
     0xD73F_0910, 0x5280_0000, 0xA90D_D27F, 0xA941_7BFD,
     0xA8C2_4FF4, 0xD65F_0FFF),
    (0xFFFF_FFFF, 0xFF00_001F, 0xFFFF_FFFF, 0xFC00_0000,
     0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFE0_001F,
     0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFE0_001F,
     0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
     0xFFFF_FFFF, 0xFFFF_FFFF),
)

# BTI C; PACIBSP; save X20/X19 and FP/LR; establish FP; keep the provider; load provider->callbackOwner (+0xd0);
# skip the release when null; ...; zero both callback slots; return 0.
VALERIA_DIRECT_CLEAR = MaskedInstructionPattern(
    'IOUSBDeviceInterface direct callback owner clear',
    (0xD503_245F, 0xD503_237F, 0xA9BE_4FF4, 0xA901_7BFD,
     0x9100_43FD, 0xAA00_03F3, 0xF940_6800, 0xB400_0000,
     0, 0, 0, 0, 0, 0, 0,
     0xA90D_7E7F, 0xF900_727F, 0x5280_0000),
    (0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
     0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFF00_001F,
     0, 0, 0, 0, 0, 0, 0,
     0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF),
)

# The same routine on kernels that predate the BTI landing pad on this kext's function entries.
VALERIA_LEGACY_DIRECT_CLEAR = MaskedInstructionPattern(
    'IOUSBDeviceInterface legacy direct callback owner clear',
    (0xD503_237F, 0xA9BE_4FF4, 0xA901_7BFD,
     0x9100_43FD, 0xAA00_03F3, 0xF940_6800, 0xB400_0000,
     0, 0, 0, 0, 0, 0, 0,
     0xA90D_7E7F, 0xF900_727F, 0x5280_0000),
    (0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF,
     0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFF00_001F,
     0, 0, 0, 0, 0, 0, 0,
     0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF),
)

# The completed function whose tail also anchors the scoped Sandbox shim's cave. That shim owns the first
# VALERIA_SANDBOX_RESERVED_WORDS words after this tail; the registration shim follows them, so the plans that use
# both shims compose without overlapping records.
VALERIA_CAVE_PREDECESSOR = MaskedInstructionPattern(
    'completed function before shared kernel executable padding',
    (0xF940_07EF, 0xF82D_798F, 0x1400_0000, 0x9100_43FF, 0xD65F_03C0),
    (0xFFFF_FFFF, 0xFFFF_FFFF, 0xFC00_0000, 0xFFFF_FFFF, 0xFFFF_FFFF),
)

VALERIA_SANDBOX_RESERVED_WORDS = 33

# The patched instruction loads callbackOwner into X8. The shim reproduces that for null and live owners. For an
# inactive owner it clears the retained owner (already on the provider command gate), restores the replacement
# user client in X1 and returns X8 == 0 so the existing CBZ enters the stock registration path.
VALERIA_DIRECT_CLEAR_CALL_INDEX = 9
VALERIA_REGISTRATION_SHIM_TEMPLATE: Tuple[Tuple[int, str], ...] = (
    (0xD503_245F, 'BTI C - indirect-call landing pad'),
    (0xD503_237F, 'PACIBSP - sign LR before making nested calls'),
    (0xA9BF_7BF5, 'STP X21,LR,[SP,#-0x10]! - preserve client and signed return'),
    (0xAA01_03F5, 'MOV X21,X1 - retain the replacement user client'),
    (0xF940_6A68, 'LDR X8,[X19,#0xd0] - reproduce the displaced owner load'),
    (0xB400_00C8, 'CBZ X8,restore - preserve the stock null-owner path'),
    (0xB940_4909, 'LDR W9,[X8,#0x48] - read the exact IOService state word'),
    (0x3600_0089, 'TBZ W9,#0,restore - keep a live owner busy'),
    (0xAA13_03E0, 'MOV X0,X19 - pass the provider to direct clear'),
    (0, 'BL direct-clear - release and zero the inactive owner'),
    (0xAA1F_03E8, 'MOV X8,XZR - enter the stock registration branch'),
    (0xAA15_03E1, 'MOV X1,X21 - restore the replacement user client'),
    (0xA8C1_7BF5, 'LDP X21,LR,[SP],#0x10 - restore state and signed return'),
    (0xD65F_0FFF, 'RETAB - authenticated return to selector-8 registration'),
)


def valeria(image: core.BinaryImage) -> List[PatchRecord]:
    """Valeria class-command registration repair: the inactive-owner check plus a registration shim assembled in
    verified executable padding. Emits kernel.valeria.class-command-registration.inactive-owner-check and
    kernel.valeria.registration-shim.<n>."""
    layout = core.MachOLayout.of(image)
    owner_load = VALERIA_OWNER_CHECK.unique_match(image, layout)
    direct_clear = _valeria_direct_clear(image, layout)
    cave = _valeria_cave(image, layout)
    shim = _valeria_registration_shim(cave, direct_clear, layout)
    redirected_owner_load = _encode_branch(True, owner_load, cave, layout,
                                           'Valeria selector-8 owner load to inactive-owner shim')

    records = [_kernel_word_patch(
        image, 'kernel.valeria.class-command-registration.inactive-owner-check', owner_load, redirected_owner_load,
        'Reclaim only an inactive Valeria callback owner before selector-8 registration',
        ('selector 8 returns kIOReturnBusy while a stale callback owner from a previous enumeration is retained',
         'the retained owner is inactive while the replacement registers on the provider command gate'))]
    for index, (word, summary) in enumerate(shim):
        records.append(_kernel_word_patch(
            image, f'kernel.valeria.registration-shim.{index}', cave + index * 4, word,
            f'Valeria inactive-owner registration shim: {summary}',
            ('reserved executable padding after the scoped Sandbox shim',
             'the shim runs inside the stock selector-8 command-gate action')))
    return records


def valeria_composite(image: core.BinaryImage) -> List[PatchRecord]:
    """The boot plans' Valeria step: skipped when the detected kernel profile lists the family as omitted."""
    profile = core.detect_kernel_profile(image)
    if profile is not None and VALERIA_NAME in profile.omitted_resolvers:
        return []
    return valeria(image)


def _valeria_direct_clear(image: core.BinaryImage, layout: core.MachOLayout) -> int:
    try:
        return VALERIA_DIRECT_CLEAR.unique_match(image, layout)
    except PatchfinderError as error:
        if error.case != 'noCandidate':
            raise
    # Pre-BTI kernels: same body and ownership semantics without the landing pad.
    return VALERIA_LEGACY_DIRECT_CLEAR.unique_match(image, layout)


def _valeria_cave(image: core.BinaryImage, layout: core.MachOLayout) -> int:
    """The registration shim's words: after the predecessor tail and the Sandbox reservation, inside one executable
    file range, zero-filled from the start of the reservation, and not targeted by any direct branch or chained
    pointer."""
    tail = VALERIA_CAVE_PREDECESSOR.unique_match(image, layout)
    sandbox_cave = tail + len(VALERIA_CAVE_PREDECESSOR.values) * 4
    cave = sandbox_cave + VALERIA_SANDBOX_RESERVED_WORDS * 4
    complete_range = range(sandbox_cave, cave + len(VALERIA_REGISTRATION_SHIM_TEMPLATE) * 4)
    cave_range = range(cave, complete_range.stop)

    if not any(r.start <= complete_range.start and r.stop >= complete_range.stop
               for r in layout.executable_file_ranges):
        raise PatchfinderError.no_candidate('file-backed executable Valeria cave')
    reserved = image.bytes_at(complete_range.start, complete_range.stop - complete_range.start)
    if reserved.count(0) != len(reserved):
        raise PatchfinderError.no_candidate('zero-filled Valeria cave after Sandbox reservation')

    # A direct branch into these words means the padding is claimed. Decoded in virtual-address space: the shim is
    # called from a fileset kext into padding owned by the kernel Mach-O.
    branches = _direct_branches_into(image, layout, cave_range)
    if branches:
        raise PatchfinderError.invalid_fixture(
            f'direct branch at {core.hex64(branches[0])} targets the proposed Valeria cave')

    # Kernel collections encode authenticated pointer targets in the low word as file offsets.
    pointers = _chained_pointers_into(image, cave_range)
    if pointers:
        raise PatchfinderError.invalid_fixture(
            f'chained pointer at {core.hex64(pointers[0])} targets the proposed Valeria cave')
    return cave


def _valeria_registration_shim(cave: int, direct_clear: int, layout: core.MachOLayout) -> List[Tuple[int, str]]:
    shim = list(VALERIA_REGISTRATION_SHIM_TEMPLATE)
    index = VALERIA_DIRECT_CLEAR_CALL_INDEX
    shim[index] = (_encode_branch(True, cave + index * 4, direct_clear, layout,
                                  'Valeria inactive callback-owner clear'), shim[index][1])
    return shim


# ================================================================================================================
# Shared helpers
# ================================================================================================================

def _kernel_word_patch(image: core.BinaryImage, record_id: str, offset: int, replacement: int, summary: str,
                       evidence: Sequence[str]) -> PatchRecord:
    """One-word kernelcache record whose original word is read from the image."""
    return PatchRecord.from_words(id=record_id, component=COMPONENT, offset=offset, original=image.read_u32(offset),
                                  replacement=replacement, summary=summary, evidence=evidence)


def _encode_branch(link: bool, source: int, target: int, layout: core.MachOLayout, description: str) -> int:
    """B/BL between two file offsets, encoded from their virtual addresses (no_candidate when out of reach)."""
    source_address = layout.virtual_address(source)
    target_address = layout.virtual_address(target)
    encoded = None
    if source_address is not None and target_address is not None:
        encoded = ARM64.encode_direct_branch(link, source_address, target_address)
    if encoded is None:
        raise PatchfinderError.no_candidate(description)
    return encoded


def _addresses_mapping_into(layout: core.MachOLayout, file_range: range) -> List[int]:
    """Every virtual address that layout.file_offset maps into `file_range` (the exact preimage)."""
    addresses = set()
    for segment in layout.segments:
        low = max(segment.file_offset, file_range.start)
        high = min(segment.file_offset + segment.file_size, file_range.stop)
        for offset in range(low, high):
            address = segment.virtual_address + (offset - segment.file_offset)
            mapped = layout.file_offset(address)
            if mapped is not None and mapped in file_range:
                addresses.add(address)
    return sorted(addresses)


def _linear_pieces(layout: core.MachOLayout, r: range):
    """(start, stop, segment or None): sub-ranges of `r` on which layout.virtual_address is a single linear map."""
    cuts = {r.start, r.stop}
    for segment in layout.segments:
        for edge in (segment.file_offset, segment.file_offset + segment.file_size):
            if r.start < edge < r.stop:
                cuts.add(edge)
    cuts = sorted(cuts)
    for start, stop in zip(cuts, cuts[1:]):
        yield start, stop, layout.segment_containing(start)


_IMM26 = 0x03FF_FFFF
_B_OPCODE_BYTE, _BL_OPCODE_BYTE = 0x14, 0x94      # top byte of B / BL with imm26[25:24] == 0


def _direct_branches_into(image: core.BinaryImage, layout: core.MachOLayout, target_range: range) -> List[int]:
    """Offsets, in executable-range order, of every aligned B/BL in an executable range whose target (decoded at
    the source's virtual address) maps back into `target_range`.

    Same result as decoding every word of every executable range, without a Python loop over all of them. At word
    index k (offset 4k, address va(k)) a branch to address t needs imm26 == ((t - va(k)) >> 2) mod 2**26, whose
    upper 10 bits (instruction bytes 2 and 3) stay constant over runs of up to 0x10000 words. Each run is searched
    for those byte-2 values (memchr over a strided copy of byte 2), byte 3 must be the B or BL opcode with the
    matching imm26[25:24], and every candidate is then verified with the exact decoder and layout maps.
    """
    targets = _addresses_mapping_into(layout, target_range)
    if not targets:
        return []
    data = image.data
    read = image.read_u32
    found: List[int] = []
    for r in layout.executable_file_ranges:
        first = (r.start + 3) & ~3
        last_stop = min(r.stop, image.count) - 3          # o + 4 <= stop  <=>  o < stop - 3
        if last_stop <= first:
            continue
        k_first = first >> 2
        k_stop = (last_stop + 3) >> 2
        byte2 = data[4 * k_first + 2:4 * k_stop:4]          # index j: byte 2 of the word at 4 * (k_first + j)
        byte3 = data[4 * k_first + 3:4 * k_stop:4]          # index j: byte 3 (opcode | imm26[25:24])
        hits = set()
        for piece_start, piece_stop, segment in _linear_pieces(layout, range(first, last_stop)):
            if segment is None:
                continue                                    # no virtual address: never a branch source
            base = segment.virtual_address - segment.file_offset          # va = base + offset on this piece
            k_low = (piece_start + 3) >> 2
            k_high = (piece_stop + 3) >> 2                                 # exclusive
            reference = targets[0]
            k = k_low
            while k < k_high:
                # Run [k, k_end): the reference target's required imm26 keeps its upper 10 bits.
                required = (((reference - (base + 4 * k)) & core.MASK64) >> 2) & _IMM26
                k_end = min(k_high, k + (required & 0xFFFF) + 1)
                uppers = set()
                for target in targets:
                    start_imm = (((target - (base + 4 * k)) & core.MASK64) >> 2) & _IMM26
                    end_imm = (start_imm - (k_end - 1 - k)) & _IMM26       # imm26 decreases as k increases
                    upper = end_imm >> 16
                    while True:
                        uppers.add(upper)
                        if upper == start_imm >> 16:
                            break
                        upper = (upper + 1) & 0x3FF
                j_end = k_end - k_first
                for upper in uppers:
                    low = upper & 0xFF
                    opcodes = (_B_OPCODE_BYTE | (upper >> 8), _BL_OPCODE_BYTE | (upper >> 8))
                    j = byte2.find(low, k - k_first, j_end)
                    while j != -1:
                        if byte3[j] in opcodes:
                            hits.add(4 * (k_first + j))
                        j = byte2.find(low, j + 1, j_end)
                k = k_end
        for offset in sorted(hits):
            source_address = layout.virtual_address(offset)
            if source_address is None:
                continue
            target_address = ARM64.direct_branch_target(read(offset), source_address)
            if target_address is None:
                continue
            target = layout.file_offset(target_address)
            if target is not None and target in target_range:
                found.append(offset)
    return found


def _chained_pointers_into(image: core.BinaryImage, target_range: range) -> List[int]:
    """8-aligned offsets p (p + 8 <= image size) whose 64-bit word has a non-zero upper half and a lower half inside
    `target_range`, ascending. Found by searching the lower half's upper three bytes, then checked exactly."""
    data = image.data
    candidates = set()
    for upper24 in sorted({value >> 8 for value in target_range if 0 <= value <= core.MASK32}):
        needle = struct.pack('<I', upper24)[:3]
        position = data.find(needle, 1)
        while position != -1:
            offset = position - 1
            if offset & 7 == 0 and offset + 8 <= image.count:
                candidates.add(offset)
            position = data.find(needle, position + 1)
    found = []
    for offset in sorted(candidates):
        pointer = image.read_u64(offset)
        if pointer >> 32 and (pointer & core.MASK32) in target_range:
            found.append(offset)
    return found
