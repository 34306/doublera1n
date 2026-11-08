"""TXM (Trusted Execution Monitor) resolver families.

Each public function takes a core.BinaryImage (the decompressed TXM Mach-O) and returns [core.PatchRecord].
PREFIXES maps every function to the record-id prefixes it can emit (used by `resolve.py --only`).

    function                      what it does                                                status
    query_module                  the three CDHash memcmp calls report equality               implemented
    constraints                   restricted-entitlement loop and signature-type checks       implemented
    boot_state                    secure-channel accessor and developer-mode publication      implemented
    debug_mapping                 the three branches that refuse a debug mapping              implemented
    debug_mapping_mark_branches   only the two address-space mark branches of debug_mapping   implemented (composition)
    permissive_flags              the code-signing policy flag block written at startup       implemented

Every site is found from code shape and string anchors in the image itself; no build-specific offsets appear in
the logic. Each family demands exactly the number of candidates it expects and fails (PatchfinderError) rather
than guess when a future build matches zero or several sites.
"""
from __future__ import annotations

from typing import List, NamedTuple, Optional, Sequence, Tuple

try:
    from . import core                     # imported as a package
except ImportError:                        # flat import: the package directory is on sys.path
    import core

PatchfinderError, PatchRecord = core.PatchfinderError, core.PatchRecord
ARM64, MachOLayout, hex64, only = core.ARM64, core.MachOLayout, core.hex64, core.only
MASK32 = core.MASK32

COMPONENT = 'TXM'
BOOT_PERMISSIVE_NAME = 'txm-boot-permissive'
CALLER_ENTITLEMENT_ID = 'txm.debug-mapping.caller-entitlement'

PREFIXES = {
    'query_module': ('txm.query-module.',),
    'constraints': ('txm.constraints.',),
    'boot_state': ('txm.secure-channel.', 'txm.developer-mode.'),
    'debug_mapping': ('txm.debug-mapping.',),
    'debug_mapping_mark_branches': ('txm.debug-mapping.',),
    'permissive_flags': ('txm.permissive-flags.',),
}


# ----------------------------------------------------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------------------------------------------------

def _record(id: str, offset: int, original: int, replacement: int, summary: str,  # noqa: A002
            evidence: Sequence[str]) -> PatchRecord:
    return PatchRecord.from_words(id=id, component=COMPONENT, offset=offset, original=original,
                                  replacement=replacement, summary=summary, evidence=evidence)


def _scan(image: core.BinaryImage, ranges: Sequence[range], values: Sequence[int],
          masks: Sequence[int]) -> List[int]:
    """Start offsets o of every n-word window (word i & masks[i] == values[i]) in the canonical per-range scan
    `o = (lo + 3) & ~3; while o + 4n <= hi; o += 4`, range by range, ascending."""
    return image.find_masked(values, masks, ranges)


def _unique_c_string(text: str, image: core.BinaryImage) -> int:
    """File offset of a whole C string: NUL on both sides, so neither a longer string ending with this text nor
    one starting with it can stand in for it."""
    hits = image.find_all(b'\0' + text.encode('utf-8') + b'\0')
    hit = only(hits)
    if hit is None:
        if not hits:
            raise PatchfinderError.missing_anchor(f'TXM string "{text}"')
        raise PatchfinderError.ambiguous_anchor(f'TXM string "{text}"', len(hits))
    return hit + 1


# ----------------------------------------------------------------------------------------------------------------
# query_module: the three CDHash memcmp calls
# ----------------------------------------------------------------------------------------------------------------

QUERY_MODULE_NAME = 'txm-query-module'

# MOV X0,Xn / MOV X1,Xn / MOV W2,#0x14 / BL / CBZ W0. MOV Xd,Xm is ORR Xd,XZR,Xm; the masks keep destination X0/X1
# and let the source registers differ between the three inlined queryModule paths.
_QUERY_VALUES = (0xAA00_03E0, 0xAA00_03E1, 0x5280_0282, 0x9400_0000, 0x3400_0000)
_QUERY_MASKS = (0xFFE0_FFFF, 0xFFE0_FFFF, MASK32, 0xFC00_0000, 0xFF00_001F)


def query_module(image: core.BinaryImage) -> List[PatchRecord]:
    """Trust-cache query-module comparisons. Emits txm.query-module.<n>.

    TXM compares two 20-byte truncated CDHashes as `MOV X0,a; MOV X1,b; MOV W2,#0x14; BL memcmp; CBZ W0,match`.
    The BL becomes MOV X0,#0 so each comparison reports equality. Exactly three such five-instruction windows
    must exist and all must call one shared memcmp. Another 20-byte comparison that loads its arguments
    differently and tests the result with CMP is excluded by the complete shape, not by position.
    """
    layout = MachOLayout.of(image)
    candidates: List[Tuple[int, int]] = []          # (BL file offset, BL target address)
    for start in _scan(image, layout.executable_file_ranges, _QUERY_VALUES, _QUERY_MASKS):
        call_offset = start + 12
        pc = layout.virtual_address(call_offset)
        if pc is None:
            continue
        target = ARM64.branch_link_target(image.read_u32(call_offset), pc)
        if target is None:
            continue
        candidates.append((call_offset, target))

    if len(candidates) != 3:
        if not candidates:
            raise PatchfinderError.no_candidate(QUERY_MODULE_NAME)
        raise PatchfinderError.ambiguous_candidate(QUERY_MODULE_NAME, [offset for offset, _ in candidates])
    if len({target for _, target in candidates}) != 1:
        raise PatchfinderError.invalid_patch(
            QUERY_MODULE_NAME, 'the three CDHash comparisons do not call one shared memcmp')

    return [
        _record(
            f'txm.query-module.{index}', offset, image.read_u32(offset), ARM64.mov_x0_zero,
            f'Make queryModule CDHash comparison {index} report equality',
            (
                'MOV X0,Xn / MOV X1,Xn / MOV W2,#0x14 / BL / CBZ W0',
                'all three selected calls target one memcmp implementation',
                'fourth 20-byte comparison rejected because it uses CMP after BL',
            ),
        )
        for index, (offset, _) in enumerate(sorted(candidates))
    ]


# ----------------------------------------------------------------------------------------------------------------
# constraints: restricted-entitlement loop and validateConstraintsSignatureType
# ----------------------------------------------------------------------------------------------------------------

CONSTRAINTS_NAME = 'txm-constraints'

# TST W0,#0xff00 / B.EQ / ADD W19,W19,#0x10,LSL#12 / ADD X21,X21,#8 / CMP X21,#0x30 / B.NE
_ENTITLEMENT_LOOP_VALUES = (0x7218_1C1F, 0x5400_0000, 0x1140_4273, 0x9100_22B5, 0xF100_C2BF, 0x5400_0001)
_ENTITLEMENT_LOOP_MASKS = (MASK32, 0xFF00_001F, MASK32, MASK32, MASK32, 0xFF00_001F)

# MOV W0,#0x30A1 / MOVK W0,#1,LSL#16: the error 0x000130A1, as raw little-endian bytes (any alignment).
_SIGNATURE_ERROR_ANCHOR = b''.join(word.to_bytes(4, 'little') for word in (0x5286_1420, 0x72A0_0020))


def _restricted_entitlement_branch(image: core.BinaryImage, ranges: Sequence[range]) -> int:
    """The B.EQ of the unique six-entry entitlement loop; both its exit and the loop's back edge point backwards.
    Branch targets are computed with file offsets as the PC (the comparison is relative to the window)."""
    candidates: List[int] = []
    for offset in _scan(image, ranges, _ENTITLEMENT_LOOP_VALUES, _ENTITLEMENT_LOOP_MASKS):
        exit_target = ARM64.conditional_target(image.read_u32(offset + 4), offset + 4)
        loop_target = ARM64.conditional_target(image.read_u32(offset + 20), offset + 20)
        if exit_target is None or loop_target is None:
            continue
        if not (exit_target < offset and loop_target < offset):
            continue
        candidates.append(offset + 4)
    candidate = only(candidates)
    if candidate is None:
        if not candidates:
            raise PatchfinderError.no_candidate(f'{CONSTRAINTS_NAME} entitlement loop')
        raise PatchfinderError.ambiguous_candidate(f'{CONSTRAINTS_NAME} entitlement loop', candidates)
    return candidate


class _SignatureBranches(NamedTuple):
    range_branch: int
    null_branch: int
    evidence: Tuple[str, ...]


def _signature_type_branches(image: core.BinaryImage) -> _SignatureBranches:
    """B.LO and CBZ X9 that skip validateConstraintsSignatureType's benign `MOV W0,#0xA1` path, located at fixed
    distances before the unique construction of error 0x000130A1 and then checked word by word."""
    anchors = image.find_all(_SIGNATURE_ERROR_ANCHOR)
    anchor = only(anchors)
    if anchor is None:
        if not anchors:
            raise PatchfinderError.missing_anchor('TXM status 0x000130A1')
        raise PatchfinderError.ambiguous_anchor('TXM status 0x000130A1', len(anchors))
    if anchor < 0x2C:
        raise PatchfinderError.no_candidate(f'{CONSTRAINTS_NAME} signature-type context')

    range_branch = anchor - 0x2C
    null_branch = anchor - 0x24
    compare = image.read_u32(range_branch - 4)
    range_word = image.read_u32(range_branch)
    load = image.read_u32(range_branch + 4)
    null = image.read_u32(null_branch)
    benign_result = image.read_u32(null_branch + 4)

    if not (compare == 0x7100_1A7F                              # CMP W19,#6
            and range_word & 0xFF00_001F == 0x5400_0003         # B.LO
            and load == 0xF940_06A9                             # LDR X9,[X21,#8]
            and null & 0xFF00_001F == 0xB400_0009               # CBZ X9
            and benign_result == 0x5280_1420):                  # MOV W0,#0xA1
        raise PatchfinderError.no_candidate(f'{CONSTRAINTS_NAME} signature-type control flow')

    return _SignatureBranches(range_branch, null_branch, (
        f'unique MOV/MOVK construction of error 0x000130A1 at {hex64(anchor)}',
        'B.LO and CBZ X9 skip the benign MOV W0,#0xA1 path',
        'fall-through branches directly to the epilogue before error construction',
    ))


def constraints(image: core.BinaryImage) -> List[PatchRecord]:
    """Constraint-validation families. Emits txm.constraints.{restricted-entitlements,signature-type-range,
    signature-type-null}.

    Two independent checks with separate anchors, so a future build cannot lose one while accidentally satisfying
    the other: the six-entry restricted-entitlement loop (returns 0x00NN30A2) and the two branches of
    validateConstraintsSignatureType that lead to error 0x000130A1. All three become NOP.
    """
    layout = MachOLayout.of(image)
    entitlement_branch = _restricted_entitlement_branch(image, layout.executable_file_ranges)
    signature = _signature_type_branches(image)
    return [
        _record(
            'txm.constraints.restricted-entitlements', entitlement_branch, image.read_u32(entitlement_branch),
            ARM64.nop, 'Do not reject the six restricted task-port entitlements',
            (
                'unique six-entry loop with TST W0,#0xff00',
                'loop advances table pointer by 8 until 0x30 bytes',
                'selected B.EQ returns the per-entry 0x00NN30A2 error',
            ),
        ),
        _record(
            'txm.constraints.signature-type-range', signature.range_branch, image.read_u32(signature.range_branch),
            ARM64.nop, 'Keep validateConstraintsSignatureType on its benign path', signature.evidence,
        ),
        _record(
            'txm.constraints.signature-type-null', signature.null_branch, image.read_u32(signature.null_branch),
            ARM64.nop, 'Do not skip to the 0x000130A1 error construction', signature.evidence,
        ),
    ]


# ----------------------------------------------------------------------------------------------------------------
# boot_state: secure-channel accessor and developer-mode publication
# ----------------------------------------------------------------------------------------------------------------

BOOT_STATE_NAME = 'txm-boot-state'

# allowedBeforeSecureChannelOperational, whole body:
#   BTI C / ADRP X9,page / ADD X9,X9,#imm / LDRB W10,[X9] / MOV W8,#1 / TBZ W10,#0 / LDRH W10,[X9,#0xc]
#   / CBNZ W10 / LDRB W8,[X9,#1]
_SECURE_ACCESSOR_VALUES = (0xD503_245F, 0x9000_0009, 0x9100_0129, 0x3940_012A, 0x5280_0028, 0x3600_000A,
                           0x7940_192A, 0x3500_000A, 0x3940_0528)
_SECURE_ACCESSOR_MASKS = (MASK32, 0x9F00_001F, 0xFFC0_03FF, MASK32, MASK32, 0xFF00_001F,
                          MASK32, 0xFF00_001F, MASK32)


def _secure_channel_accessor(image: core.BinaryImage, ranges: Sequence[range]) -> int:
    candidates = _scan(image, ranges, _SECURE_ACCESSOR_VALUES, _SECURE_ACCESSOR_MASKS)
    candidate = only(candidates)
    if candidate is None:
        if not candidates:
            raise PatchfinderError.no_candidate(f'{BOOT_STATE_NAME} secure accessor')
        raise PatchfinderError.ambiguous_candidate(f'{BOOT_STATE_NAME} secure accessor', candidates)
    return candidate


def _developer_mode_branch(image: core.BinaryImage, layout: core.MachOLayout, state_offset: int) -> int:
    """The `TBZ W9 / MOV W20,#1 / B` right after an `ADRP X19 / ADD X19,X19` of the shared state structure: the
    branch that otherwise skips publishing developer mode as true."""
    candidates: List[int] = []
    for reference in layout.adrp_add_references(state_offset):
        adrp = image.read_u32(reference.adrp_offset)
        add = image.read_u32(reference.add_offset)
        if not (adrp & 0x1F == 19 and add & 0x1F == 19 and (add >> 5) & 0x1F == 19
                and reference.add_offset + 12 < image.count):
            continue
        branch_offset = reference.add_offset + 4
        branch = image.read_u32(branch_offset)
        set_true = image.read_u32(branch_offset + 4)
        forward = image.read_u32(branch_offset + 8)
        if not (branch & 0xFF00_001F == 0x3600_0009            # TBZ W9
                and set_true == 0x5280_0034                     # MOV W20,#1
                and forward & 0xFC00_0000 == 0x1400_0000):      # B
            continue
        candidates.append(branch_offset)
    candidate = only(candidates)
    if candidate is None:
        if not candidates:
            raise PatchfinderError.no_candidate(f'{BOOT_STATE_NAME} developer mode')
        raise PatchfinderError.ambiguous_candidate(f'{BOOT_STATE_NAME} developer mode', candidates)
    return candidate


def boot_state(image: core.BinaryImage) -> List[PatchRecord]:
    """Secure-channel and developer-mode state publication. Emits txm.secure-channel.{return-one,return} and
    txm.developer-mode.publish.

    The secure-channel accessor is identified by its full body; its ADRP/ADD gives the state structure, which
    in turn anchors the developer-mode branch in the routine that publishes into it. The accessor's BTI landing
    pad is kept: its ADRP/ADD become MOV X0,#1 / RET, and the developer-mode TBZ becomes NOP.
    """
    layout = MachOLayout.of(image)
    secure_entry = _secure_channel_accessor(image, layout.executable_file_ranges)
    adrp_offset = secure_entry + 4
    add_offset = secure_entry + 8

    pc = layout.virtual_address(adrp_offset)
    if pc is None:
        raise PatchfinderError.invalid_fixture('secure-channel accessor is outside mapped code')
    adrp = image.read_u32(adrp_offset)
    add = image.read_u32(add_offset)
    state_address = (ARM64.adrp_target(adrp, pc) + ARM64.add_immediate(add)) & core.MASK64
    state_offset = layout.file_offset(state_address)
    if state_offset is None:
        raise PatchfinderError.invalid_fixture('TXM state structure is outside mapped segments')

    dev_mode_branch = _developer_mode_branch(image, layout, state_offset)
    shared_evidence = (
        f'unique secure-channel accessor body begins at {hex64(secure_entry)}',
        f'accessor and developer-mode routine reference state at {hex64(state_offset)}',
        'BTI landing pad is preserved; replacement begins after it',
    )
    return [
        _record(
            'txm.secure-channel.return-one', adrp_offset, adrp, ARM64.mov_x0_one,
            'Make allowedBeforeSecureChannelOperational return true', shared_evidence,
        ),
        _record(
            'txm.secure-channel.return', add_offset, add, ARM64.ret,
            'Return immediately after setting the secure-channel result', shared_evidence,
        ),
        _record(
            'txm.developer-mode.publish', dev_mode_branch, image.read_u32(dev_mode_branch), ARM64.nop,
            'Take the existing path that publishes developer mode as true',
            shared_evidence + (
                'TBZ W9,#0 otherwise skips MOV W20,#1',
                'NOP preserves TXM\'s existing propagation and final store',
            ),
        ),
    ]


# ----------------------------------------------------------------------------------------------------------------
# debug_mapping: the three branches that refuse a debug mapping
# ----------------------------------------------------------------------------------------------------------------

DEBUG_MAPPING_NAME = 'txm-debug-mapping'
DEBUGGER_ENTITLEMENT = 'com.apple.private.cs.debugger'
ERROR_37_MESSAGE = 'disallowed non-debugger initiated debug mapping'
ERROR_30_MESSAGE = 'disallowed writable debug mapping due to address space'


def _is_tbnz_bit_zero(word: int) -> bool:
    """TBNZ Wt,#0,<label>: b5 (bit 31) and b40 (bits 23:19) zero select bit 0 of a W register."""
    return word & 0xFFF8_0000 == 0x3700_0000


def _is_movz32(word: int, immediate: int) -> bool:
    """MOVZ Wd,#imm with no shift, any Rd."""
    return word & 0xFFFF_FFE0 == 0x5280_0000 | (immediate << 5)


def _only_reference(offset: int, layout: core.MachOLayout, what: str) -> core.ADRPAddReference:
    refs = layout.adrp_add_references(offset)
    reference = only(refs)
    if reference is None:
        if not refs:
            raise PatchfinderError.missing_anchor(f'{DEBUG_MAPPING_NAME} {what} reference')
        raise PatchfinderError.ambiguous_anchor(f'{DEBUG_MAPPING_NAME} {what} reference', len(refs))
    return reference


def _function_bounds(offset: int, image: core.BinaryImage, layout: core.MachOLayout) -> Tuple[int, int]:
    start = ARM64.function_start(offset, image, layout)
    if start is None:
        raise PatchfinderError.no_candidate(f'{DEBUG_MAPPING_NAME} function containing {hex64(offset)}')
    return start, ARM64.next_function_start(start, image, layout)


def _mark_check(site: int, image: core.BinaryImage) -> Optional[Tuple[int, int]]:
    """`ADD Xk,Xn,#0x30 ; LDARB Wt,[Xk] ; TBNZ Wt,#0,allow` with the TBNZ at `site` -> (site, allow).

    The acquire load of byte +0x30 is how both readers consume the address-space mark; requiring the register
    chain stops an unrelated TBNZ that happens to sit nearby from matching.
    """
    if site < 8:
        return None
    add = image.read_u32(site - 8)
    load = image.read_u32(site - 4)
    test = image.read_u32(site)
    if add & 0xFFFF_FC00 != 0x9100_C000:       # ADD Xd,Xn,#0x30 (64-bit, no shift)
        return None
    if load & 0xFFFF_FC00 != 0x08DF_FC00:      # LDARB Wt,[Xn]
        return None
    if not ((load >> 5) & 0x1F == add & 0x1F and _is_tbnz_bit_zero(test) and test & 0x1F == load & 0x1F):
        return None
    allow = ARM64.test_branch_target(test, site)
    if allow is None:
        return None
    return site, allow


def _entitlement_allow_target(refs: Sequence[core.ADRPAddReference], function: int, end: int,
                              image: core.BinaryImage) -> int:
    """Where holding the debugger entitlement jumps inside one function: ADRP/ADD of the entitlement name, the
    query BL within the next few words, then `TBNZ W0,#0,allow` directly after the BL."""
    inside = [ref for ref in refs if function <= ref.add_offset < end]
    reference = only(inside)
    if reference is None:
        name = f'{DEBUG_MAPPING_NAME} entitlement check in {hex64(function)}'
        if not inside:
            raise PatchfinderError.no_candidate(name)
        raise PatchfinderError.ambiguous_candidate(name, [ref.add_offset for ref in inside])
    cursor = reference.add_offset + 4
    while cursor < min(end, reference.add_offset + 4 * 6):
        word = image.read_u32(cursor)
        if ARM64.branch_link_target(word, cursor) is not None:
            test = image.read_u32(cursor + 4)
            allow = ARM64.test_branch_target(test, cursor + 4) if test & 0xFFF8_001F == 0x3700_0000 else None
            if allow is None:
                break
            return allow
        cursor += 4
    raise PatchfinderError.no_candidate(f'{DEBUG_MAPPING_NAME} entitlement result in {hex64(function)}')


class _Handler(NamedTuple):
    function: int
    caller_site: int
    allow: int
    mark_site: int
    mark_allow: int


def _resolve_handler(image: core.BinaryImage, layout: core.MachOLayout,
                     entitlement_refs: Sequence[core.ADRPAddReference]) -> _Handler:
    """Selector-42 handler: the error-37 caller-entitlement decision and the error-29 address-space mark check."""
    message = _unique_c_string(ERROR_37_MESSAGE, image)
    reference = _only_reference(message, layout, 'error-37 message')
    function, end = _function_bounds(reference.adrp_offset, image, layout)

    # The word before the message's ADRP is the decision: TBNZ Wt,#0 jumps over the logging and error assignment.
    caller_site = reference.adrp_offset - 4
    caller = image.read_u32(caller_site)
    allow = ARM64.test_branch_target(caller, caller_site) if _is_tbnz_bit_zero(caller) else None
    if allow is None or not function <= allow < end:
        raise PatchfinderError.no_candidate(f'{DEBUG_MAPPING_NAME} error-37 decision')
    # ADRP/ADD message, BL log, MOV Wd,#0x25: the skipped path really produces error 37.
    log = image.read_u32(reference.add_offset + 4)
    status = image.read_u32(reference.add_offset + 8)
    if ARM64.branch_link_target(log, reference.add_offset + 4) is None or not _is_movz32(status, 0x25):
        raise PatchfinderError.no_candidate(f'{DEBUG_MAPPING_NAME} error-37 refusal path')
    entitled = _entitlement_allow_target(entitlement_refs, function, end, image)
    if entitled != allow:
        raise PatchfinderError.invalid_patch(
            DEBUG_MAPPING_NAME,
            f'error-37 TBNZ targets {hex64(allow)} but the entitlement allows at {hex64(entitled)}')

    marks: List[Tuple[int, int]] = []
    cursor = function
    while cursor + 16 <= end:
        match = _mark_check(cursor + 8, image)
        if (match is not None and _is_movz32(image.read_u32(cursor + 12), 0x1D)
                and function <= match[1] < end):
            marks.append(match)
        cursor += 4
    mark = only(marks)
    if mark is None:
        if not marks:
            raise PatchfinderError.no_candidate(f'{DEBUG_MAPPING_NAME} error-29 decision')
        raise PatchfinderError.ambiguous_candidate(f'{DEBUG_MAPPING_NAME} error-29 decision',
                                                   [site for site, _ in marks])
    return _Handler(function, caller_site, allow, mark[0], mark[1])


class _Validator(NamedTuple):
    function: int
    site: int
    allow: int


def _resolve_validator(image: core.BinaryImage, layout: core.MachOLayout,
                       entitlement_refs: Sequence[core.ADRPAddReference]) -> _Validator:
    """Writable/executable debug-mapping validator: the error-30 mark check right before its message."""
    message = _unique_c_string(ERROR_30_MESSAGE, image)
    reference = _only_reference(message, layout, 'error-30 message')
    function, end = _function_bounds(reference.adrp_offset, image, layout)

    mark = _mark_check(reference.adrp_offset - 4, image) if reference.adrp_offset >= function + 12 else None
    if mark is None or not function <= mark[1] < end:
        raise PatchfinderError.no_candidate(f'{DEBUG_MAPPING_NAME} validator mark check')
    entitled = _entitlement_allow_target(entitlement_refs, function, end, image)
    if entitled != mark[1]:
        raise PatchfinderError.invalid_patch(
            DEBUG_MAPPING_NAME,
            f'validator TBNZ targets {hex64(mark[1])} but the entitlement allows at {hex64(entitled)}')
    return _Validator(function, mark[0], mark[1])


def _forced_branch(id: str, site: int, target: int, image: core.BinaryImage, summary: str,  # noqa: A002
                   evidence: Sequence[str]) -> PatchRecord:
    """The TBNZ at `site` becomes an unconditional B to the target it already names."""
    branch = ARM64.encode_direct_branch(False, site, target)
    if branch is None:
        raise PatchfinderError.invalid_patch(id, f'B to {hex64(target)} is out of range')
    return _record(id, site, image.read_u32(site), branch, summary,
                   tuple(evidence) + (f'TBNZ at {hex64(site)} becomes B to its own target {hex64(target)}',))


def debug_mapping(image: core.BinaryImage) -> List[PatchRecord]:
    """The three debug-mapping branches. Emits txm.debug-mapping.{caller-entitlement,address-space,
    validator-address-space}.

    A debug mapping is what lets a code page made writable (vm_protect VM_PROT_COPY) become executable again.
    Three existing TBNZ instructions whose taken edge is the allow path decide it; each becomes an unconditional
    B to the target it already names, so no control flow is invented:

      * error 37 (selector-42 handler): the caller lacks com.apple.private.cs.debugger and a policy byte is clear;
      * error 29 (same handler): the address space is not marked;
      * error 30 (the writable debug-mapping validator, a different function): neither entitlement nor mark.

    Each site is tied to the entitlement check in its own function: the forced branch must name the same target
    that holding the entitlement already jumps to.
    """
    layout = MachOLayout.of(image)
    entitlement = _unique_c_string(DEBUGGER_ENTITLEMENT, image)
    entitlement_refs = layout.adrp_add_references(entitlement)

    handler = _resolve_handler(image, layout, entitlement_refs)
    validator = _resolve_validator(image, layout, entitlement_refs)
    if validator.function == handler.function:
        raise PatchfinderError.invalid_patch(
            DEBUG_MAPPING_NAME, 'the validator and the selector-42 handler resolved to one function')

    return [
        _forced_branch(
            CALLER_ENTITLEMENT_ID, handler.caller_site, handler.allow, image,
            'Allow a debug mapping requested without com.apple.private.cs.debugger',
            (
                f'unique "{ERROR_37_MESSAGE}" reference in {hex64(handler.function)}',
                f'TBNZ immediately before it skips to {hex64(handler.allow)}, the same target the entitlement '
                f'result branches to',
                'the refusal path sets error 0x25 (37)',
            ),
        ),
        _forced_branch(
            'txm.debug-mapping.address-space', handler.mark_site, handler.mark_allow, image,
            'Allow a debug mapping for an address space that is not marked',
            (
                f'ADD #0x30 / LDARB / TBNZ #0 / MOV #0x1d is unique in {hex64(handler.function)}',
                'the fall-through sets error 0x1d (29)',
            ),
        ),
        _forced_branch(
            'txm.debug-mapping.validator-address-space', validator.site, validator.allow, image,
            'Let the debug-mapping validator accept an address space that is not marked',
            (
                f'unique "{ERROR_30_MESSAGE}" reference in {hex64(validator.function)}',
                'ADD #0x30 / LDARB / TBNZ #0 immediately before it reads the same mark',
                f'TBNZ target {hex64(validator.allow)} equals the entitlement result\'s allow target',
            ),
        ),
    ]


def debug_mapping_mark_branches(image: core.BinaryImage) -> List[PatchRecord]:
    """The boot-permissive plan's debug-mapping step: the two address-space mark branches only.

    The caller-entitlement branch is left stock because the permissive task_for_pid flag is the byte it tests.
    """
    branches = [r for r in debug_mapping(image) if r.id != CALLER_ENTITLEMENT_ID]
    if len(branches) != 2:
        raise PatchfinderError.invalid_patch(
            BOOT_PERMISSIVE_NAME, f'expected the two address-space branches, got {len(branches)}')
    return branches


# ----------------------------------------------------------------------------------------------------------------
# permissive_flags: the code-signing policy flag block written once at startup
# ----------------------------------------------------------------------------------------------------------------

PERMISSIVE_FLAGS_NAME = 'txm-permissive-flags'
INTERNAL_VARIANT_MESSAGE = 'resolving to internal device variant due to fusing state'
MOV_X0_MINUS_ONE = 0x9280_0000           # MOVN X0,#0, i.e. MOV X0,#-1


class _Store(NamedTuple):
    size: int
    rt: int
    rn: int
    offset: int


class _LoadByte(NamedTuple):
    rt: int
    rn: int
    offset: int


def _decode_store(word: int) -> Optional[_Store]:
    """STRB/STRH Wt,[Xn,#imm] (unsigned offset); the offset is imm12 scaled by the access size."""
    kind = word & 0xFFC0_0000
    if kind == 0x3900_0000:
        size = 1
    elif kind == 0x7900_0000:
        size = 2
    else:
        return None
    return _Store(size, word & 0x1F, (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) * size)


def _decode_load_byte(word: int) -> Optional[_LoadByte]:
    """LDRB Wt,[Xn,#imm] (unsigned offset)."""
    if word & 0xFFC0_0000 != 0x3940_0000:
        return None
    return _LoadByte(word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF)


class _FlagBlock(NamedTuple):
    trust_site: int
    trust_offset: int
    local_signing_site: int
    local_signing_offset: int
    profile_site: int
    profile_offset: int
    debug_site: int
    y: int


def _flag_block(call: int, image: core.BinaryImage) -> _FlagBlock:
    """The nine words after the internal-variant call:

        LDRB Wt,[B,#k] / STRH WZR,[B,#X-3] / STRB W0,[B,#X] / STRB WZR,[B,#X-1] / STRH WZR,[B,#X+1]
        / UBFX Wt,Wt,#1,#1 / STRB Wt,[B,#X+3] / STRH WZR,[B,#Y] / STRB WZR,[B,#Y+6]

    One base register throughout; offsets are checked relative to the W0 store, never against absolute values,
    because the structure moves between builds.
    """
    fail = PatchfinderError.no_candidate(f'{PERMISSIVE_FLAGS_NAME} flag store block after {hex64(call)}')
    words = [image.read_u32(call + index * 4) for index in range(1, 10)]

    load = _decode_load_byte(words[0])
    trust = _decode_store(words[1])
    internal_ca = _decode_store(words[2])
    local_signing = _decode_store(words[3])
    core_trust = _decode_store(words[4])
    profile = _decode_store(words[6])
    debug = _decode_store(words[7])
    udid = _decode_store(words[8])
    if not (load is not None
            and trust is not None and trust.size == 2 and trust.rt == 31
            and internal_ca is not None and internal_ca.size == 1 and internal_ca.rt == 0
            and local_signing is not None and local_signing.size == 1 and local_signing.rt == 31
            and core_trust is not None and core_trust.size == 2 and core_trust.rt == 31
            # UBFX Wt,Wt,#1,#1 is UBFM Wd,Wn,#1,#1: 0x53010400 | Rn<<5 | Rd.
            and words[5] == 0x5301_0400 | (load.rt << 5) | load.rt
            and profile is not None and profile.size == 1 and profile.rt == load.rt
            and debug is not None and debug.size == 2 and debug.rt == 31
            and udid is not None and udid.size == 1 and udid.rt == 31):
        raise fail

    base = internal_ca.rn
    x = internal_ca.offset
    # The LDRB sits between the call and the W0 stores; loading into W0 would overwrite the all-ones value.
    if not (load.rt != 0 and load.rt != 31
            and base != 0 and base != load.rt and base != 31
            and all(rn == base for rn in (load.rn, trust.rn, local_signing.rn, core_trust.rn, profile.rn,
                                          debug.rn, udid.rn))
            and x >= 3
            and trust.offset == x - 3
            and local_signing.offset == x - 1
            and core_trust.offset == x + 1
            and profile.offset == x + 3
            and debug.offset > x + 3
            and udid.offset == debug.offset + 6):
        raise fail

    return _FlagBlock(
        trust_site=call + 8, trust_offset=trust.offset,
        local_signing_site=call + 16, local_signing_offset=local_signing.offset,
        profile_site=call + 28, profile_offset=profile.offset,
        debug_site=call + 32, y=debug.offset,
    )


def _selector42_policy_byte(image: core.BinaryImage) -> int:
    """Offset of the config byte the selector-42 handler tests right before its error-37 branch: the
    `LDRB Wt,[Xn,#imm]` immediately ahead of the TBNZ that debug_mapping resolves as caller-entitlement."""
    branch = next((r for r in debug_mapping(image) if r.id == CALLER_ENTITLEMENT_ID), None)
    fail = PatchfinderError.no_candidate(f'{PERMISSIVE_FLAGS_NAME} selector-42 policy byte')
    if branch is None or branch.offset < 4:
        raise fail
    load = _decode_load_byte(image.read_u32(branch.offset - 4))
    test = branch.original_word
    if load is None or test is None or test & 0x1F != load.rt:      # the TBNZ tests the byte just loaded
        raise fail
    return load.offset


def _callers(function: int, image: core.BinaryImage, layout: core.MachOLayout) -> List[int]:
    """Every BL in the executable segments whose target is `function`. File offsets stand in for addresses:
    caller and callee share one segment, so the PC-relative target agrees."""
    read = image.read_u32
    return [offset for offset in image.find_word(0x9400_0000, 0xFC00_0000, layout.executable_file_ranges)
            if ARM64.branch_link_target(read(offset), offset) == function]


def permissive_flags(image: core.BinaryImage) -> List[PatchRecord]:
    """Permissive policy flags (any signature, local signing, profile trust, CS enforcement, task_for_pid).
    Emits txm.permissive-flags.*.

    Release TXM hardcodes its code-signing policy flags in one store block after the only call to the function
    that logs the internal-variant message (it returns 1 only on internal-fused hardware). That call becomes
    MOV X0,#-1 and the four stores of the permissive flags store W0 instead; the CoreTrust and UDID fields keep
    their zero. The task_for_pid halfword Y is tied to the selector-42 handler: Y+1 must be the byte tested just
    before the error-37 branch, which is why boot-permissive leaves that branch stock.
    """
    layout = MachOLayout.of(image)
    message = _unique_c_string(INTERNAL_VARIANT_MESSAGE, image)
    refs = layout.adrp_add_references(message)
    reference = only(refs)
    if reference is None:
        if not refs:
            raise PatchfinderError.missing_anchor(f'{PERMISSIVE_FLAGS_NAME} internal-variant reference')
        raise PatchfinderError.ambiguous_anchor(f'{PERMISSIVE_FLAGS_NAME} internal-variant reference', len(refs))
    check = ARM64.function_start(reference.adrp_offset, image, layout)
    if check is None:
        raise PatchfinderError.no_candidate(f'{PERMISSIVE_FLAGS_NAME} internal-variant function')

    calls = _callers(check, image, layout)
    call = only(calls)
    if call is None:
        if not calls:
            raise PatchfinderError.no_candidate(f'{PERMISSIVE_FLAGS_NAME} internal-variant caller')
        raise PatchfinderError.ambiguous_candidate(f'{PERMISSIVE_FLAGS_NAME} internal-variant caller', calls)
    block = _flag_block(call, image)

    task_for_pid = _selector42_policy_byte(image)
    if task_for_pid != block.y + 1:
        raise PatchfinderError.invalid_patch(
            PERMISSIVE_FLAGS_NAME,
            f'flag halfword at +{hex64(block.y)} but the selector-42 handler tests +{hex64(task_for_pid)}')

    shape = ('BL internal-variant check / LDRB / STRH / STRB W0 / STRB / STRH / UBFX / STRB / STRH / STRB at '
             + hex64(call))

    def store_w0(id: str, site: int, summary: str, evidence: str) -> PatchRecord:  # noqa: A002
        """Same store with Rt cleared to W0; size, base and offset unchanged."""
        original = image.read_u32(site)
        return _record(id, site, original, original & ~0x1F & MASK32, summary,
                       (evidence, 'store keeps its size, base and offset; source becomes W0'))

    return [
        _record(
            'txm.permissive-flags.all-ones', call, image.read_u32(call), MOV_X0_MINUS_ONE,
            'Replace the internal-device result with all ones for every flag stored from W0',
            (
                shape,
                f'BL target {hex64(check)} is the only function referencing the internal-variant message',
                'this is its only caller',
            ),
        ),
        store_w0('txm.permissive-flags.skip-trust-any-signature', block.trust_site,
                 f'Turn on skip trust evaluation and allow any signature (+{hex64(block.trust_offset)})', shape),
        store_w0('txm.permissive-flags.local-signing', block.local_signing_site,
                 f'Turn on unrestricted local signing (+{hex64(block.local_signing_offset)})', shape),
        store_w0('txm.permissive-flags.profile-trust', block.profile_site,
                 f'Turn on relaxed profile trust (+{hex64(block.profile_offset)})', shape),
        store_w0('txm.permissive-flags.cs-enforcement-task-for-pid', block.debug_site,
                 f'Turn on CS enforcement disable and unrestricted task_for_pid (+{hex64(block.y)})',
                 f'{shape}; +{hex64(block.y + 1)} is the byte the selector-42 handler tests'),
    ]
