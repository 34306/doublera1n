"""Userland daemon resolver families (thin arm64e Mach-O executables from the root filesystem).

Each public function takes a core.BinaryImage (the daemon file itself; offsets are file offsets) and returns
[core.PatchRecord]. Objective-C lookups go through objc.ObjCMetadata. PREFIXES maps every function to the
record-id prefixes it can emit (used by `resolve.py --only`).

    function            what it does                                                 status
    commcenter          the three CommCenter data-activation gates                   implemented
    coreauthd           skip the startController call that enters the DTO ratchet    implemented
    ctkd                -[TKSEPKeyServer serverAttributesOfKey:error:] returns nil   implemented
    mobileactivationd   should_hactivate getter and activation-state report          implemented

Nothing here is keyed to a build: every site is found from a string / selector / CFString anchor and then
required to have a specific instruction shape, with a uniqueness check at each step (no candidate ->
PatchfinderError.no_candidate, several -> ambiguous_candidate).
"""
from __future__ import annotations

from typing import List, NamedTuple, Optional, Tuple

try:
    from . import core, objc
except ImportError:                        # flat import: the package directory is on sys.path
    import core
    import objc

ARM64, MachOLayout = core.ARM64, core.MachOLayout
PatchfinderError, PatchRecord = core.PatchfinderError, core.PatchRecord
hex64 = core.hex64

PREFIXES = {
    'commcenter': ('commcenter.data-connection.', 'commcenter.data-settings.'),
    'coreauthd': ('coreauthd.dto-ratchet.',),
    'ctkd': ('ctkd.sep-key-server.',),
    'mobileactivationd': ('mobileactivationd.should-hactivate', 'mobileactivationd.activation-state.'),
}

RETAB = 0xD65F_0FFF


def _executable_range_containing(layout: MachOLayout, offset: int) -> Optional[range]:
    """First executable segment file range containing `offset`."""
    return next((r for r in layout.executable_file_ranges if offset in r), None)


# ================================================================================================================
# CommCenter: three data-activation gates
# ================================================================================================================
#
#   1. canActivateWithoutOverrides returns "context is not assigned" (status -3) when no PDP context index has been
#      allocated yet, before it evaluates anything:
#          cmn  w8, #2 ; b.ne <evaluation> ; mov w8, #-3 ; adrp x9, "context is not assigned"
#      The B.NE becomes an unconditional B to its own target (a NOP would fall into the -3 block, and the flags
#      after the preceding load would be meaningless anyway).
#   2. canActivateDataSettings refuses with -3 / "ActivationStatus failed in DataSettings" when the
#      ActivationStatus virtual (vtable slot 0x4C0) answers false:
#          blraa x8, x16 ; tbz w0, #0, failure ... failure: mov w8, #-3 ; ... adrp x8, <message>
#      The TBZ that targets the failure block's MOVN and follows a BLRAA becomes a NOP.
#   3. activateDataSettings asks the same virtual again and refuses with "can not activate with current baseband
#      activated state"; the TBZ W0,#0 after `mov x17,#0x4c0 ... blraa` jumps back into that refusal block and
#      becomes a NOP.

_CC_NAME = 'commcenter-data-activation'
_CC_COMPONENT = 'CommCenter'
_CC_ACTIVATION_ANCHOR = 'ActivationStatus failed in DataSettings'
_CC_CONTEXT_ANCHOR = 'context is not assigned'
# The whole stored literal (the bare suffix is not NUL-terminated on its own and so not findable as a literal).
_CC_BASEBAND_STATE_ANCHOR = 'activateDataSettings: can not activate with current baseband activated state'

_MOVN_W8_2 = 0x1280_0048                  # MOVN W8,#2 == MOV W8,#-3: first instruction of the -3 failure block
_CMN_W8_2 = 0x3100_091F                   # CMN W8,#2 (ADDS WZR,W8,#2): compare with the unassigned sentinel -2
_BCOND_MASK, _BCOND_OPCODE, _COND_NE = 0xFF00_0010, 0x5400_0000, 0x1
_FAILURE_BLOCK_SEARCH_WORDS = 6           # how far before the string reference the MOVN may sit
_TBZ_MASK, _TBZ_W0_BIT0 = 0xFFF8_001F, 0x3600_0000   # TBZ W0,#0,<label> (displacement free)
_BLRAA_MASK, _BLRAA_OPCODE = 0xFFFF_FC00, 0xD73F_0800  # BLRAA Xn,Xm
_MOV_X17_ACTIVATION_SLOT = 0xD280_9811    # MOV X17,#0x4C0: ActivationStatus vtable slot discriminator
_SLOT_SEARCH_WORDS = 10                   # how far before the BLRAA the slot constant may sit
_REFUSAL_BLOCK_SEARCH_WORDS = 24          # how far back the TBZ may jump into the refusal block


def _unique_literal(image: core.BinaryImage, literal: str) -> int:
    anchors = image.find_all_utf8(literal, nul_terminated=True)
    if len(anchors) != 1:
        if not anchors:
            raise PatchfinderError.missing_anchor(literal)
        raise PatchfinderError.ambiguous_anchor(literal, len(anchors))
    return anchors[0]


def _unique_reference(layout: MachOLayout, offset: int, description: str) -> core.ADRPAddReference:
    references = layout.adrp_add_references(offset)
    if len(references) != 1:
        if not references:
            raise PatchfinderError.no_candidate(description)
        raise PatchfinderError.ambiguous_candidate(description, [r.adrp_offset for r in references])
    return references[0]


def _tbz_w0_bit0_sites(image: core.BinaryImage, layout: MachOLayout) -> List[int]:
    """Every TBZ W0,#0 word in the executable ranges (range by range, ascending), the scan both TBZ gates share."""
    return image.memo(('userland.tbz_w0_bit0',),
                      lambda: image.find_word(_TBZ_W0_BIT0, _TBZ_MASK, layout.executable_file_ranges))


def _cc_context_gate(image: core.BinaryImage, layout: MachOLayout) -> PatchRecord:
    anchor_offset = _unique_literal(image, _CC_CONTEXT_ANCHOR)
    reference = _unique_reference(layout, anchor_offset, f'{_CC_NAME} context message xref')

    # The anchor is the reason string: the patch site is two words before its ADRP, framed by CMN and MOVN.
    if reference.adrp_offset < 12:
        raise PatchfinderError.no_candidate(f'{_CC_NAME} context gate window')
    branch_offset = reference.adrp_offset - 8
    if image.read_u32(reference.adrp_offset - 4) != _MOVN_W8_2:
        raise PatchfinderError.no_candidate(f'{_CC_NAME} context gate status store')
    if image.read_u32(reference.adrp_offset - 12) != _CMN_W8_2:
        raise PatchfinderError.no_candidate(f'{_CC_NAME} context gate sentinel compare')

    branch = image.read_u32(branch_offset)
    if branch & _BCOND_MASK != _BCOND_OPCODE or branch & 0xF != _COND_NE:
        raise PatchfinderError.no_candidate(f'{_CC_NAME} context gate branch')

    # The destination must be code in the branch's own executable segment, not merely a mapped address.
    code = _executable_range_containing(layout, branch_offset)
    branch_address = layout.virtual_address(branch_offset)
    target = target_offset = replacement = None
    if code is not None and branch_address is not None:
        target = ARM64.conditional_target(branch, branch_address)
        if target is not None:
            target_offset = layout.file_offset(target)
            if target_offset is not None and target_offset in code:
                replacement = ARM64.encode_direct_branch(False, branch_address, target)
    if replacement is None:
        raise PatchfinderError.no_candidate(f'{_CC_NAME} context gate retarget')

    return PatchRecord.from_words(
        id='commcenter.data-connection.context-index',
        component=_CC_COMPONENT,
        offset=branch_offset,
        original=branch,
        replacement=replacement,
        summary='Stop canActivateWithoutOverrides refusing before it evaluates, for want of a context index',
        evidence=[
            f'unique "{_CC_CONTEXT_ANCHOR}" literal at {hex64(anchor_offset)}',
            f'unique ADRP+ADD reference at {hex64(reference.adrp_offset)}',
            'preceded by CMN W8,#2 and MOVN W8,#2',
            f'B.NE retargeted to its own destination {hex64(target)} unconditionally',
        ],
    )


def _cc_activation_status_gate(image: core.BinaryImage, layout: MachOLayout) -> PatchRecord:
    anchor_offset = _unique_literal(image, _CC_ACTIVATION_ANCHOR)
    reference = _unique_reference(layout, anchor_offset, f'{_CC_NAME} message xref')

    # Walk back from the string reference to the MOVN W8,#2 that stores -3: the address the gate must target.
    failure_offset = None
    for step in range(1, _FAILURE_BLOCK_SEARCH_WORDS + 1):
        candidate = reference.adrp_offset - step * 4
        if candidate < 0:
            break
        if image.read_u32(candidate) == _MOVN_W8_2:
            failure_offset = candidate
            break
    if failure_offset is None:
        raise PatchfinderError.no_candidate(f'{_CC_NAME} failure block entry')
    failure_address = layout.virtual_address(failure_offset)
    if failure_address is None:
        raise PatchfinderError.no_candidate(f'{_CC_NAME} failure block address')

    read = image.read_u32
    candidates = []
    for offset in _tbz_w0_bit0_sites(image, layout):
        if offset < 4:
            continue
        address = layout.virtual_address(offset)
        if address is None or ARM64.test_branch_target(read(offset), address) != failure_address:
            continue
        # The gate branches on the virtual call's result: the previous word must be an authenticated call.
        if read(offset - 4) & _BLRAA_MASK != _BLRAA_OPCODE:
            continue
        candidates.append(offset)

    if len(candidates) != 1:
        if not candidates:
            raise PatchfinderError.no_candidate(_CC_NAME)
        raise PatchfinderError.ambiguous_candidate(_CC_NAME, candidates)
    patch_offset = candidates[0]

    return PatchRecord.from_words(
        id='commcenter.data-settings.activation-status',
        component=_CC_COMPONENT,
        offset=patch_offset,
        original=read(patch_offset),
        replacement=ARM64.nop,
        summary='Stop canActivateDataSettings refusing a data context for activation status',
        evidence=[
            f'unique "{_CC_ACTIVATION_ANCHOR}" literal at {hex64(anchor_offset)}',
            f'unique ADRP+ADD reference at {hex64(reference.adrp_offset)}',
            f'MOVN W8,#2 failure-block entry at {hex64(failure_offset)}',
            'single TBZ W0,#0 to that block preceded by BLRAA',
        ],
    )


def _materialises_activation_slot(image: core.BinaryImage, call_offset: int) -> bool:
    """MOV X17,#0x4C0 within the search window ending just before the BLRAA at `call_offset`."""
    for step in range(1, _SLOT_SEARCH_WORDS + 1):
        candidate = call_offset - step * 4
        if candidate < 0:
            return False
        if image.read_u32(candidate) == _MOV_X17_ACTIVATION_SLOT:
            return True
    return False


def _cc_activate_baseband_state_gate(image: core.BinaryImage, layout: MachOLayout) -> PatchRecord:
    anchor_offset = _unique_literal(image, _CC_BASEBAND_STATE_ANCHOR)
    reference = _unique_reference(layout, anchor_offset, f'{_CC_NAME} baseband-state message xref')
    reference_address = layout.virtual_address(reference.adrp_offset)
    if reference_address is None:
        raise PatchfinderError.no_candidate(f'{_CC_NAME} baseband-state reference address')

    read = image.read_u32
    window = _REFUSAL_BLOCK_SEARCH_WORDS * 4
    candidates = []
    for offset in _tbz_w0_bit0_sites(image, layout):
        if offset < 4:
            continue
        address = layout.virtual_address(offset)
        if address is None:
            continue
        target = ARM64.test_branch_target(read(offset), address)
        if target is None:
            continue
        # The refusal block lies behind the branch and contains the string reference: a short backward jump.
        if not (target <= reference_address and reference_address - target <= window):
            continue
        if read(offset - 4) & _BLRAA_MASK != _BLRAA_OPCODE:
            continue
        if not _materialises_activation_slot(image, offset - 4):
            continue
        candidates.append(offset)

    if len(candidates) != 1:
        if not candidates:
            raise PatchfinderError.no_candidate(f'{_CC_NAME} baseband-state gate')
        raise PatchfinderError.ambiguous_candidate(f'{_CC_NAME} baseband-state gate', candidates)
    patch_offset = candidates[0]

    return PatchRecord.from_words(
        id='commcenter.data-settings.activate-baseband-state',
        component=_CC_COMPONENT,
        offset=patch_offset,
        original=read(patch_offset),
        replacement=ARM64.nop,
        summary='Stop activateDataSettings refusing the activation it was just told it could do',
        evidence=[
            f'unique "{_CC_BASEBAND_STATE_ANCHOR}" literal at {hex64(anchor_offset)}',
            f'unique ADRP+ADD reference at {hex64(reference.adrp_offset)}',
            'single TBZ W0,#0 branching back into that block, preceded by BLRAA',
            'MOV X17,#0x4C0 pins it to vtable slot 1216, the same virtual as gate two',
        ],
    )


def commcenter(image: core.BinaryImage) -> List[PatchRecord]:
    """CommCenter data activation. Emits commcenter.data-connection.context-index and
    commcenter.data-settings.{activation-status,activate-baseband-state}."""
    layout = MachOLayout.of(image)
    return [
        _cc_context_gate(image, layout),
        _cc_activation_status_gate(image, layout),
        _cc_activate_baseband_state_gate(image, layout),
    ]


# ================================================================================================================
# coreauthd: skip the startController call that enters the SEP-backed DTO ratchet
# ================================================================================================================

_LDR_X0_SP_8 = 0xF940_07E0                # LDR X0,[SP,#8]: the instruction after the call (its return address)


def coreauthd(image: core.BinaryImage) -> List[PatchRecord]:
    """Skip the BL to the startController selector stub whose completion enters the SEP-backed DTO ratchet.
    Emits coreauthd.dto-ratchet.start-controller.

    The selector's optimized objc_msgSend stub must be unique, and exactly one BL in executable code may call it
    with LDR X0,[SP,#8] as the next instruction; that BL becomes a NOP."""
    name = 'coreauthd'
    metadata = objc.ObjCMetadata(image)
    stubs = metadata.selector_stubs('startController')
    if len(stubs) != 1:
        if not stubs:
            raise PatchfinderError.no_candidate(f'{name} selector stub')
        raise PatchfinderError.ambiguous_candidate(f'{name} selector stub', [s.stub_offset for s in stubs])
    stub = stubs[0]

    layout = metadata.layout
    callers = []
    # BL <anything> ; LDR X0,[SP,#8] with both words in range (offset + 8 <= range end), then the exact BL target.
    for offset in image.find_masked((0x9400_0000, _LDR_X0_SP_8), (0xFC00_0000, core.MASK32),
                                    layout.executable_file_ranges):
        call_address = layout.virtual_address(offset)
        if call_address is None:
            continue
        if ARM64.branch_link_target(image.read_u32(offset), call_address) == stub.stub_address:
            callers.append(offset)

    if len(callers) != 1:
        if not callers:
            raise PatchfinderError.no_candidate(name)
        raise PatchfinderError.ambiguous_candidate(name, callers)
    call_offset = callers[0]

    return [
        PatchRecord.from_words(
            id='coreauthd.dto-ratchet.start-controller',
            component='coreauthd',
            offset=call_offset,
            original=image.read_u32(call_offset),
            replacement=ARM64.nop,
            summary='Skip the SEP-dependent DTO ratchet controller startup',
            evidence=[
                'unique startController selector and Objective-C selector reference',
                f'optimized objc_msgSend selector stub at {hex64(stub.stub_offset)}',
                'unique BL caller followed by LDR X0,[SP,#8] at crash return address',
            ],
        ),
    ]


# ================================================================================================================
# ctkd: -[TKSEPKeyServer serverAttributesOfKey:error:] returns nil
# ================================================================================================================

def ctkd(image: core.BinaryImage) -> List[PatchRecord]:
    """Make -[TKSEPKeyServer serverAttributesOfKey:error:] return nil. Emits ctkd.sep-key-server.{return-nil,return}.

    The selector must have exactly one implementation, and its entry must look like a real arm64e function start
    (RETAB before it, PACIBSP at it, SUB SP,SP,#imm after it) so a coincidental relative-method decode cannot
    become a patch. PACIBSP -> MOV X0,#0 and the frame allocation -> RET."""
    name = 'ctkd'
    metadata = objc.ObjCMetadata(image)
    methods = metadata.methods('serverAttributesOfKey:error:')
    if len(methods) != 1:
        if not methods:
            raise PatchfinderError.no_candidate(name)
        raise PatchfinderError.ambiguous_candidate(name, [m.implementation_offset for m in methods])
    method = methods[0]

    entry = method.implementation_offset
    landing_pad = image.read_u32(entry)
    stack_frame = image.read_u32(entry + 4)
    if not (entry >= 4
            and image.read_u32(entry - 4) == RETAB
            and landing_pad == ARM64.pacibsp
            and stack_frame & 0xFFC0_03FF == 0xD100_03FF):     # SUB SP,SP,#imm
        raise PatchfinderError.invalid_patch(name, 'resolved method does not have the expected arm64e entry frame')

    evidence = [
        'unique Objective-C selector serverAttributesOfKey:error:',
        f'relative method entry at {hex64(method.entry_offset)} resolves to {hex64(entry)}',
        'RETAB / PACIBSP / SUB SP,SP entry boundary',
    ]
    return [
        PatchRecord.from_words(
            id='ctkd.sep-key-server.return-nil',
            component='ctkd',
            offset=entry,
            original=landing_pad,
            replacement=ARM64.mov_x0_zero,
            summary='Return nil from serverAttributesOfKey:error:',
            evidence=evidence,
        ),
        PatchRecord.from_words(
            id='ctkd.sep-key-server.return',
            component='ctkd',
            offset=entry + 4,
            original=stack_frame,
            replacement=ARM64.ret,
            summary='Return before entering the SEP-backed method body',
            evidence=evidence,
        ),
    ]


# ================================================================================================================
# mobileactivationd: should_hactivate getter + activation-state report
# ================================================================================================================
#
# getActivationStateWithCompletionBlock: has a data-migration gate `TBZ W22,#0,<fallback>` within its first 0x300
# bytes. Two code shapes are recognised at that gate:
#   legacy               gate + 0x60 is ADRP X8 ; ADD X8,X8,#imm ; LDR X0,[X8,#imm] (load of a state global).
#                        Patch: NOP the gate, and turn the load into ADRP X0 ; ADD X0,X0 ; NOP = &CFString"Activated".
#   dictionary fallback  the TBZ target builds a one-entry NSDictionary (key load, value load, stack slots,
#                        dictionaryWithObjects:forKeys:count:). Patch: gate -> B fallback, and turn the value load
#                        (fallback + 16) into ADRP X8 ; ADD X8,X8 ; NOP = &CFString"Activated".
# The legacy shape takes precedence: on builds that have it the TBZ target also matches the dictionary shape, and
# accepting both at one gate would leave no method with exactly one candidate.

_MAD_NAME = 'mobileactivationd'
_MAD_COMPONENT = 'mobileactivationd'
_ACTIVATION_STATE_SELECTOR = 'getActivationStateWithCompletionBlock:'
_LDRB_W0_X0_MASK, _LDRB_W0_X0 = 0xFFC0_03FF, 0x3940_0000   # LDRB W0,[X0,#imm]
_TBZ_W22_BIT0 = 0x3600_0016                                # TBZ W22,#0,<label> under _TBZ_MASK
_STATE_SCAN_WINDOW = 0x300
_LEGACY_LOAD_DISTANCE = 0x60
_DICTIONARY_FALLBACK_BYTES = 0x38

# (word index, mask, value) of the 14-instruction dictionary fallback.
_DICTIONARY_FALLBACK_SHAPE: Tuple[Tuple[int, int, int], ...] = (
    (0, 0x9F00_001F, 0x9000_0008),          # ADRP X8,<key page>
    (1, 0xFFC0_03FF, 0x9100_0108),          # ADD  X8,X8,#imm
    (2, core.MASK32, 0xF940_0108),          # LDR  X8,[X8]
    (3, core.MASK32, 0xF900_0FE8),          # STR  X8,[SP,#0x18]
    (4, 0x9F00_001F, 0x9000_0008),          # ADRP X8,<value page>     <- patched (load)
    (5, 0xFFC0_03FF, 0x9100_0108),          # ADD  X8,X8,#imm          <- patched
    (6, core.MASK32, 0xF940_0108),          # LDR  X8,[X8]             <- patched
    (7, core.MASK32, 0xF900_13E8),          # STR  X8,[SP,#0x20]
    (8, 0x9F00_001F, 0x9000_0008),          # ADRP X8,<selector page>
    (9, 0xFFC0_03FF, 0xF940_0100),          # LDR  X0,[X8,#imm]
    (10, core.MASK32, 0x9100_83E2),         # ADD  X2,SP,#0x20
    (11, core.MASK32, 0x9100_63E3),         # ADD  X3,SP,#0x18
    (12, core.MASK32, 0x5280_0024),         # MOV  W4,#1
    (13, 0xFC00_0000, 0x9400_0000),         # BL   <msgSend>
)


class _StateLoadCandidate(NamedTuple):
    gate: int
    load: int
    fallback: int
    kind: str                               # 'legacy' | 'dictionary-fallback'


def _state_load_candidates(image: core.BinaryImage, method_offset: int,
                           executable: range) -> List[_StateLoadCandidate]:
    """Migration-gate candidates in the first 0x300 bytes of the method, bounded by its executable range (so a
    drifted TBZ target in an adjacent non-executable section is never matched as instructions)."""
    read = image.read_u32
    matches: List[_StateLoadCandidate] = []
    end = min(executable.stop, method_offset + _STATE_SCAN_WINDOW)
    gate = method_offset
    while gate + 4 <= end:
        branch = read(gate)
        if branch & _TBZ_MASK != _TBZ_W22_BIT0:
            gate += 4
            continue
        load_offset = gate + _LEGACY_LOAD_DISTANCE
        found_legacy = False
        if load_offset + 12 <= end:
            adrp, add, load = read(load_offset), read(load_offset + 4), read(load_offset + 8)
            if (adrp & 0x9F00_001F == 0x9000_0008           # ADRP X8,<page>
                    and add & 0xFFC0_03FF == 0x9100_0108    # ADD X8,X8,#imm
                    and load & 0xFFC0_03FF == 0xF940_0100):  # LDR X0,[X8,#imm]
                matches.append(_StateLoadCandidate(gate, load_offset, 0, 'legacy'))
                found_legacy = True

        # Legacy precedence (see the section comment). The TBZ target is computed in file-offset space (both ends
        # are in the same segment); comparisons are ordered so nothing can wrap.
        if not found_legacy:
            fallback = ARM64.test_branch_target(branch, gate)
            if (fallback is not None and fallback >= method_offset and fallback <= end
                    and end - fallback >= _DICTIONARY_FALLBACK_BYTES
                    and all(read(fallback + 4 * index) & mask == value
                            for index, mask, value in _DICTIONARY_FALLBACK_SHAPE)):
                matches.append(_StateLoadCandidate(gate, fallback + 16, fallback, 'dictionary-fallback'))
        gate += 4
    return matches


def _hactivation_getter(metadata: objc.ObjCMetadata) -> objc.ObjCMethod:
    image = metadata.image
    getters = []
    for method in metadata.methods('should_hactivate'):
        entry = method.implementation_offset
        if entry + 8 > image.count:
            continue
        if image.read_u32(entry) & _LDRB_W0_X0_MASK == _LDRB_W0_X0 and image.read_u32(entry + 4) == ARM64.ret:
            getters.append(method)
    if len(getters) != 1:
        if not getters:
            raise PatchfinderError.no_candidate(f'{_MAD_NAME}.should_hactivate')
        raise PatchfinderError.ambiguous_candidate(f'{_MAD_NAME}.should_hactivate',
                                                   [m.implementation_offset for m in getters])
    return getters[0]


def _activation_state_method(metadata: objc.ObjCMetadata) -> objc.ObjCMethod:
    # The selector also has a forwarding/protocol implementation; only the daemon's own method has exactly one
    # migration-gate candidate. A method outside every executable range is simply not a candidate.
    matches = []
    for method in metadata.methods(_ACTIVATION_STATE_SELECTOR):
        executable = _executable_range_containing(metadata.layout, method.implementation_offset)
        if executable is None:
            continue
        if len(_state_load_candidates(metadata.image, method.implementation_offset, executable)) == 1:
            matches.append(method)
    if len(matches) != 1:
        name = f'{_MAD_NAME}.{_ACTIVATION_STATE_SELECTOR}'
        if not matches:
            raise PatchfinderError.no_candidate(name)
        raise PatchfinderError.ambiguous_candidate(name, [m.implementation_offset for m in matches])
    return matches[0]


def _hactivation_getter_patch(image: core.BinaryImage, method: objc.ObjCMethod) -> PatchRecord:
    entry = method.implementation_offset
    load = image.read_u32(entry)
    # A synthesized BOOL getter is exactly LDRB W0,[X0,#ivar] ; RET (the ivar offset may move).
    if not (load & _LDRB_W0_X0_MASK == _LDRB_W0_X0 and image.read_u32(entry + 4) == ARM64.ret):
        raise PatchfinderError.invalid_patch(f'{_MAD_NAME}.should_hactivate',
                                             'selector does not resolve to a two-instruction BOOL getter')
    return PatchRecord.from_words(
        id='mobileactivationd.should-hactivate',
        component=_MAD_COMPONENT,
        offset=entry,
        original=load,
        replacement=ARM64.mov_w0_one,
        summary='Make DeviceType report that hactivation is enabled',
        evidence=[
            'unique Objective-C selector should_hactivate',
            f'relative method entry resolves to {hex64(entry)}',
            'two-instruction LDRB W0,[X0,#ivar] / RET getter',
        ],
    )


def _constant_string(text: str, metadata: objc.ObjCMetadata) -> Tuple[int, int]:
    """(file offset, address) of the unique 32-byte __DATA_CONST,__cfstring object whose length is len(text) and
    whose chained-rebase backing pointer lands on a NUL-terminated `text` in __TEXT,__cstring."""
    image, layout = metadata.image, metadata.layout
    strings = layout.section('__cstring', segment='__TEXT')
    constants = layout.section('__cfstring', segment='__DATA_CONST')
    if strings is None or constants is None:
        raise PatchfinderError.invalid_fixture('Mach-O lacks CFString backing sections')
    c_strings = [o for o in image.find_all_utf8(text, nul_terminated=True) if o in strings.file_range]
    if not c_strings:
        raise PatchfinderError.missing_anchor(text)
    c_string_addresses = {a for a in (layout.virtual_address(o) for o in c_strings) if a is not None}

    length = len(text.encode('utf-8'))
    matches: List[Tuple[int, int]] = []
    r = constants.file_range
    offset = r.start
    while offset + 32 <= r.stop:
        if image.read_u64(offset + 24) == length:
            backing = metadata.chained_rebase_target(offset + 16)
            if backing is not None and backing in c_string_addresses:
                address = layout.virtual_address(offset)
                if address is not None:
                    matches.append((offset, address))
        offset += 32

    if len(matches) != 1:
        if not matches:
            raise PatchfinderError.no_candidate(f'CFString {text}')
        raise PatchfinderError.ambiguous_candidate(f'CFString {text}', [m[0] for m in matches])
    return matches[0]


def _activation_state_patches(image: core.BinaryImage, metadata: objc.ObjCMetadata,
                              method: objc.ObjCMethod) -> List[PatchRecord]:
    activated_object = _constant_string('Activated', metadata)
    executable = _executable_range_containing(metadata.layout, method.implementation_offset)
    if executable is None:
        raise PatchfinderError.no_candidate(
            f'{_MAD_NAME}.activation-state: the method is outside every executable range')
    candidates = _state_load_candidates(image, method.implementation_offset, executable)
    if len(candidates) != 1:
        if not candidates:
            raise PatchfinderError.no_candidate(f'{_MAD_NAME}.activation-state')
        raise PatchfinderError.ambiguous_candidate(f'{_MAD_NAME}.activation-state', [c.gate for c in candidates])
    candidate = candidates[0]

    if candidate.kind == 'dictionary-fallback':
        return _dictionary_fallback_patches(image, metadata, method, candidate, activated_object)

    object_offset, object_address = activated_object
    adrp_address = metadata.layout.virtual_address(candidate.load)
    replacement_adrp = replacement_add = None
    if adrp_address is not None:
        replacement_adrp = ARM64.encode_adrp(0, adrp_address, object_address)
        if replacement_adrp is not None:
            replacement_add = ARM64.encode_add_immediate(0, 0, object_address & 0xFFF)
    if replacement_add is None:
        raise PatchfinderError.invalid_patch(f'{_MAD_NAME}.activation-state',
                                             'Activated CFString cannot be encoded as ADRP+ADD X0')

    evidence = [
        f'unique {_ACTIVATION_STATE_SELECTOR} implementation at {hex64(method.implementation_offset)}',
        'TBZ W22,#0 data-migration gate followed 0x60 bytes later by ADRP/ADD/LDR fallback load',
        f'unique 32-byte CFString object for Activated at {hex64(object_offset)}',
    ]
    read = image.read_u32
    return [
        PatchRecord.from_words(
            id='mobileactivationd.activation-state.migration-gate', component=_MAD_COMPONENT,
            offset=candidate.gate, original=read(candidate.gate), replacement=ARM64.nop,
            summary='Do not skip activation-state reporting before migration completes', evidence=evidence),
        PatchRecord.from_words(
            id='mobileactivationd.activation-state.adrp', component=_MAD_COMPONENT,
            offset=candidate.load, original=read(candidate.load), replacement=replacement_adrp,
            summary='Load the page containing the Activated CFString', evidence=evidence),
        PatchRecord.from_words(
            id='mobileactivationd.activation-state.add', component=_MAD_COMPONENT,
            offset=candidate.load + 4, original=read(candidate.load + 4), replacement=replacement_add,
            summary='Materialize the Activated CFString address in X0', evidence=evidence),
        PatchRecord.from_words(
            id='mobileactivationd.activation-state.dereference', component=_MAD_COMPONENT,
            offset=candidate.load + 8, original=read(candidate.load + 8), replacement=ARM64.nop,
            summary='Keep the CFString object address instead of dereferencing a state global', evidence=evidence),
    ]


def _dictionary_fallback_patches(image: core.BinaryImage, metadata: objc.ObjCMetadata, method: objc.ObjCMethod,
                                 candidate: _StateLoadCandidate,
                                 activated_object: Tuple[int, int]) -> List[PatchRecord]:
    """Route every call through the one-entry dictionary fallback and replace only its value load."""
    object_offset, object_address = activated_object
    layout = metadata.layout
    gate_address = layout.virtual_address(candidate.gate)
    fallback_address = layout.virtual_address(candidate.fallback)
    load_address = layout.virtual_address(candidate.load)
    branch = adrp = add = None
    if gate_address is not None and fallback_address is not None and load_address is not None:
        branch = ARM64.encode_direct_branch(False, gate_address, fallback_address)
        if branch is not None:
            adrp = ARM64.encode_adrp(8, load_address, object_address)
            if adrp is not None:
                add = ARM64.encode_add_immediate(8, 8, object_address & 0xFFF)
    if add is None:
        raise PatchfinderError.invalid_patch(f'{_MAD_NAME}.activation-state',
                                             'dictionary fallback branch or Activated CFString is not encodable')

    evidence = [
        f'unique {_ACTIVATION_STATE_SELECTOR} implementation at {hex64(method.implementation_offset)}',
        'TBZ migration gate targets a one-entry dictionary fallback',
        'key and value loads occupy distinct stack slots',
        f'unique Activated CFString object at {hex64(object_offset)}',
    ]
    read = image.read_u32
    return [
        PatchRecord.from_words(
            id='mobileactivationd.activation-state.migration-gate', component=_MAD_COMPONENT,
            offset=candidate.gate, original=read(candidate.gate), replacement=branch,
            summary='Route activation-state reporting through the dictionary fallback', evidence=evidence),
        PatchRecord.from_words(
            id='mobileactivationd.activation-state.adrp', component=_MAD_COMPONENT,
            offset=candidate.load, original=read(candidate.load), replacement=adrp,
            summary='Load the page containing the Activated CFString', evidence=evidence),
        PatchRecord.from_words(
            id='mobileactivationd.activation-state.add', component=_MAD_COMPONENT,
            offset=candidate.load + 4, original=read(candidate.load + 4), replacement=add,
            summary='Materialize the Activated CFString address in X8', evidence=evidence),
        PatchRecord.from_words(
            id='mobileactivationd.activation-state.dereference', component=_MAD_COMPONENT,
            offset=candidate.load + 8, original=read(candidate.load + 8), replacement=ARM64.nop,
            summary='Store the Activated object instead of loading a default state', evidence=evidence),
    ]


def mobileactivationd(image: core.BinaryImage) -> List[PatchRecord]:
    """Activation-state and should-hactivate patches. Emits mobileactivationd.should-hactivate and
    mobileactivationd.activation-state.{migration-gate,adrp,add,dereference}."""
    metadata = objc.ObjCMetadata(image)
    should_hactivate = _hactivation_getter(metadata)
    activation_state = _activation_state_method(metadata)
    getter_patch = _hactivation_getter_patch(image, should_hactivate)
    state_patches = _activation_state_patches(image, metadata, activation_state)
    return [getter_patch] + state_patches
