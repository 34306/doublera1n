"""Kernel Sandbox MACF hook patches and the code-signing (JIT) patches.

Each public function takes a core.BinaryImage (the decompressed kernelcache) and returns [core.PatchRecord];
kernel_policy.py re-exports them (its PREFIXES table covers their record ids).

    function               what it does                                            status
    sandbox                Sandbox MACF hooks, optional scoped vnode-open shim     implemented
    vm_fault_cs_bypass     NOP the vm_fault_enter cs_bypass test                   implemented
    ppl_allow_invalid      pmap allow-invalid                                      stub (profile opt-in only)
    vm_map_protect         vm_map_protect keeps execute permission                 stub (profile opt-in only)

The two stubs raise NotImplementedError. They are only reached when a kernel profile opts in: kernel_policy's
codesigning_required runs them when the detected profile has a 'kernel-codesign-invalid' variant, and no registered
profile has one yet.

Scans that conceptually test every word of the whole kernel are done with byte searches (regex / bytes.find on
fixed opcode bytes), and every hit is then re-checked with the exact per-word predicate, so the candidate sets,
their order and the first-reported offender are the same as a word-by-word scan would give.
"""
from __future__ import annotations

import re
import struct
from typing import List, Optional, Sequence, Tuple

try:
    from . import core
except ImportError:
    import core

PatchfinderError, PatchRecord = core.PatchfinderError, core.PatchRecord
ARM64, MASK32, hex64 = core.ARM64, core.MASK32, core.hex64

_COMPONENT = 'kernelcache'


def _patch(image: core.BinaryImage, id: str, offset: int, replacement: int, summary: str,  # noqa: A002
           evidence: Sequence[str]) -> PatchRecord:
    """One-word record whose original word is read (bounds-checked) from the image."""
    return PatchRecord.from_words(id=id, component=_COMPONENT, offset=offset, original=image.read_u32(offset),
                                  replacement=replacement, summary=summary, evidence=evidence)


# ================================================================================================================
# Sandbox: mac_policy_conf -> mpc_ops -> native MACF hooks
# ================================================================================================================
#
# The anchors are data structures rather than function bodies:
#
#     "Sandbox" + "Seatbelt sandbox policy" -> mac_policy_conf -> mpc_ops (+0x20) -> chained hook pointers
#
# The low 32 bits of each chained pointer are the hook's file offset. Without the scoped vnode-open shim the
# result is the 11 established table/function records; with it, 35 more records (slot retarget, slot metadata
# assertion, 33-word shim in verified zero-filled executable padding).

_MPC_OPS_FIELD = 0x20
_MPC_OPS_SLOTS = 268
_SLOT_VNODE_CHECK_EXEC = 258
_SLOT_VNODE_CHECK_OPEN = 267

# (record id stem, hook name, mpc_ops index) of the hooks turned into `mov x0, #0 ; ret`.
_SANDBOX_STUBS: Tuple[Tuple[str, str, int], ...] = (
    ('file-check-mmap', 'file_check_mmap', 36),
    ('mount-check-mount', 'mount_check_mount', 87),
    ('mount-check-remount', 'mount_check_remount', 88),
    ('mount-check-unmount', 'mount_check_umount', 91),
    ('vnode-check-rename', 'vnode_check_rename', 120),
)

# PACIBSP; save FP/LR; establish FP; MRS X0,TPIDR_EL1; LDR X1,[X0,#0x408]; ADRP X8,<page>; ADD X8,X8,#0x1f0;
# LDP X9,X8,[X8]. Branch/ADRP fields and (data-layout drift) load/ADD immediates are relaxed.
_CURRENT_THREAD_RO = core.MaskedInstructionPattern.from_reference_words(
    'current_thread_ro',
    [0xD503_237F, 0xA9BF_7BFD, 0x9100_03FD, 0xD538_D080, 0xF942_0401, 0xB0FE_C908, 0x9107_C108, 0xA940_2109],
    allow_data_layout_drift=True,
)

# LDR X15,[SP,#8]; STR X15,[X12,X13,LSL#3]; B <any>; ADD SP,SP,#0x10; RET -- the completed function whose end
# is followed by unclaimed, file-backed __text padding.
_CAVE_PREDECESSOR = core.MaskedInstructionPattern(
    'completed function immediately before Sandbox executable cave',
    [0xF940_07EF, 0xF82D_798F, 0x1400_0000, 0x9100_43FF, 0xD65F_03C0],
    [0xFFFF_FFFF, 0xFFFF_FFFF, 0xFC00_0000, 0xFFFF_FFFF, 0xFFFF_FFFF],
)

# Position-independent shim body. The three zero words are external branches encoded for the chosen cave
# (index, link). Internal branches stay valid because they move with the whole body.
_SHIM_TEMPLATE: Tuple[Tuple[int, str], ...] = (
    (0xD503237F, 'PACIBSP - sign LR with the B key and SP'),
    (0xA9BD7BFD, 'STP FP,LR,[SP,#-0x30]! - save frame and signed LR'),
    (0x910003FD, 'MOV FP,SP - establish the frame pointer'),
    (0xA90107E0, 'STP X0,X1,[SP,#0x10] - save vnode hook arguments'),
    (0xA9020FE2, 'STP X2,X3,[SP,#0x20] - save vnode hook arguments'),
    (0, 'BL current_thread_ro - encoded after resolving the target'),
    (0xF9400C00, 'LDR X0,[X0,#0x18] - load thread_ro->tro_proc'),
    (0xB4000240, 'CBZ X0,native - null proc takes the native policy path'),
    (0, 'BL proc_best_name - encoded after resolving the target'),
    (0xF9400008, 'LDR X8,[X0] - load the first eight process-name bytes'),
    (0xD28CAA49, 'MOV X9,#0x6552 - materialize Resolver bytes 0..1'),
    (0xF2ADEE69, 'MOVK X9,#0x6f73,LSL#16 - Resolver bytes 2..3'),
    (0xF2CECD89, 'MOVK X9,#0x766c,LSL#32 - Resolver bytes 4..5'),
    (0xF2EE4CA9, 'MOVK X9,#0x7265,LSL#48 - Resolver bytes 6..7'),
    (0xEB09011F, 'CMP X8,X9 - compare the Resolver prefix'),
    (0x54000140, 'B.EQ native - Resolver takes the native policy path'),
    (0xD28D2CC9, 'MOV X9,#0x6966 - materialize fileprov bytes 0..1'),
    (0xF2ACAD89, 'MOVK X9,#0x656c,LSL#16 - fileprov bytes 2..3'),
    (0xF2CE4E09, 'MOVK X9,#0x7270,LSL#32 - fileprov bytes 4..5'),
    (0xF2EECDE9, 'MOVK X9,#0x766f,LSL#48 - fileprov bytes 6..7'),
    (0xEB09011F, 'CMP X8,X9 - compare the fileprov prefix'),
    (0x54000080, 'B.EQ native - fileprov takes the native policy path'),
    (0x52800000, 'MOV W0,#0 - return success for other processes'),
    (0xA8C37BFD, 'LDP FP,LR,[SP],#0x30 - restore the allow-path frame'),
    (0xD65F0FFF, 'RETAB - authenticated allow-path return'),
    (0xA94107E0, 'LDP X0,X1,[SP,#0x10] - restore native arguments'),
    (0xA9420FE2, 'LDP X2,X3,[SP,#0x20] - restore native arguments'),
    (0xA8C37BFD, 'LDP FP,LR,[SP],#0x30 - restore native-path frame'),
    (0xD50323FF, 'AUTIBSP - authenticate LR before the original PACIBSP'),
    (0xCA1E07D0, 'EOR X16,X30,X30,LSL#1 - prepare the LR integrity test'),
    (0xB6F00050, 'TBZ X16,#62,native - valid LR proceeds to the tail call'),
    (0xD4388E20, 'BRK #0xc471 - trap if LR authentication failed'),
    (0, 'B vnode_check_open - encoded after resolving the target'),
)
_SHIM_BRANCH_CURRENT_THREAD_RO = 5
_SHIM_BRANCH_PROC_BEST_NAME = 8
_SHIM_BRANCH_VNODE_CHECK_OPEN = 32


def sandbox(image: core.BinaryImage, include_scoped_vnode_open: bool = True) -> List[PatchRecord]:
    """Sandbox MACF operation-table / hook patches; with include_scoped_vnode_open also the scoped vnode-open shim.
    Emits kernel.sandbox.*."""
    operations = _sandbox_operations_table(image)
    targets = {index: _operation_target(image, operations, index) for _, _, index in _SANDBOX_STUBS}
    file_check_mmap = targets[36]
    vnode_check_exec_slot = operations + _SLOT_VNODE_CHECK_EXEC * 8
    patches: List[PatchRecord] = []

    if include_scoped_vnode_open:
        layout = core.MachOLayout.of(image)
        vnode_check_open_slot = operations + _SLOT_VNODE_CHECK_OPEN * 8
        vnode_check_open = image.read_u32(vnode_check_open_slot)
        current_thread_ro = _CURRENT_THREAD_RO.unique_match(image, layout)
        proc_best_name = _resolve_proc_best_name(image, layout)
        cave = _resolve_executable_cave(image, layout)
        shim = _build_open_shim(cave, current_thread_ro, proc_best_name, vnode_check_open)

        patches.append(_patch(
            image, 'kernel.sandbox.vnode-check-open.target', vnode_check_open_slot, cave,
            'Retarget vnode_check_open to the scoped process-name shim',
            ['mac_policy_conf -> mpc_ops[267]', 'low chained-pointer target only']))
        # Deliberate no-op record: asserts the slot's authenticated-pointer metadata word while leaving it intact.
        patches.append(_patch(
            image, 'kernel.sandbox.vnode-check-open.metadata', vnode_check_open_slot + 4,
            image.read_u32(vnode_check_open_slot + 4),
            'Assert and preserve vnode_check_open PAC metadata',
            ['high chained-pointer word from mpc_ops[267]']))
        for index, (word, summary) in enumerate(shim):
            patches.append(_patch(
                image, f'kernel.sandbox.vnode-check-open.shim.{index}', cave + index * 4, word,
                f'Scoped vnode_check_open shim: {summary}',
                ['unique executable cave after reviewed function tail']))

    # vnode_check_exec is pointed at the mpc_ops[36] hook, which becomes an allow stub below. Only the low target
    # word changes; the slot's own PAC metadata stays in the untouched high word.
    patches.append(_patch(
        image, 'kernel.sandbox.vnode-check-exec.target', vnode_check_exec_slot, file_check_mmap,
        'Retarget vnode_check_exec to the existing allow stub',
        ['mac_policy_conf -> mpc_ops[258]', 'mpc_ops[36] target']))

    for stem, name, index in _SANDBOX_STUBS:
        # A slot stores the address an indirect call lands on: on a BTI build that is the landing pad, so the stub
        # starts one word later and the pad survives.
        start = ARM64.stub_start(targets[index], image)
        if image.read_u32(start) != ARM64.pacibsp:
            raise PatchfinderError.no_candidate(f'{name} PACIBSP entry')
        patches.append(_patch(
            image, f'kernel.sandbox.{stem}.result', start, ARM64.mov_x0_zero,
            f'Return success from {name}', ['native target read from its mpc_ops slot']))
        patches.append(_patch(
            image, f'kernel.sandbox.{stem}.return', start + 4, ARM64.ret,
            'Return the forced Seatbelt result', ['paired entry-point stub']))
    return patches


def _sandbox_operations_table(image: core.BinaryImage) -> int:
    """The unique mac_policy_conf whose first two pointers name the Sandbox policy; returns its mpc_ops offset."""
    sandbox_strings = image.find_all_utf8('Sandbox', nul_terminated=True)
    description_strings = image.find_all_utf8('Seatbelt sandbox policy', nul_terminated=True)
    if not sandbox_strings:
        raise PatchfinderError.missing_anchor('Sandbox')
    if not description_strings:
        raise PatchfinderError.missing_anchor('Seatbelt sandbox policy')
    sandbox_targets = {offset & MASK32 for offset in sandbox_strings}
    description_targets = {offset & MASK32 for offset in description_strings}

    # Equivalent to testing every 8-aligned offset o (o + 40 <= count) for low32(qword o) in sandbox_targets and
    # low32(qword o + 8) in description_targets: search the rarer field's values and check the other field.
    data, count, read = image.data, image.count, image.read_u32
    if len(description_targets) <= len(sandbox_targets):
        needles, field, other_field, other = description_targets, 8, 0, sandbox_targets
    else:
        needles, field, other_field, other = sandbox_targets, 0, 8, description_targets
    candidates = set()
    for value in needles:
        needle = struct.pack('<I', value)
        hit = data.find(needle, field)
        while hit != -1:
            offset = hit - field
            if offset & 7 == 0 and offset + 40 <= count and read(offset + other_field) in other:
                candidates.add(offset)
            hit = data.find(needle, hit + 1)
    ordered = sorted(candidates)
    if len(ordered) != 1:
        if not ordered:
            raise PatchfinderError.no_candidate('Sandbox mac_policy_conf')
        raise PatchfinderError.ambiguous_candidate('Sandbox mac_policy_conf', ordered)

    operations = read(ordered[0] + _MPC_OPS_FIELD)
    if operations % 8 or operations + _MPC_OPS_SLOTS * 8 > count:
        raise PatchfinderError.invalid_fixture('Sandbox mpc_ops pointer is outside the image')
    return operations


def _operation_target(image: core.BinaryImage, table: int, index: int) -> int:
    target = image.read_u32(table + index * 8)
    if target + 8 > image.count:
        raise PatchfinderError.invalid_fixture(f'mpc_ops[{index}] target is outside the image')
    return target


# -- proc_best_name: six-instruction leaf identified by data flow ------------------------------------------------

# ADD Xd,Xn,#imm ; LDRB Wt,[Xn,#imm] ; ADD Xd,Xn,#imm ; CMP Wn,#0 ; CSEL Xd,Xn,Xm,cond ; RET (opcode classes only;
# operands are related by _is_proc_best_name).
_PROC_BEST_NAME_VALUES = (0x9100_0000, 0x3940_0000, 0x9100_0000, 0x7100_001F, 0x9A80_0000, 0xD65F_03C0)
_PROC_BEST_NAME_MASKS = (0xFFC0_0000, 0xFFC0_0000, 0xFFC0_0000, 0xFFFF_FC1F, 0xFFE0_0C00, 0xFFFF_FFFF)


def _resolve_proc_best_name(image: core.BinaryImage, layout: core.MachOLayout) -> int:
    """p_name must immediately follow the 17-byte p_comm and the CSEL must implement the empty-name fallback into
    x0; register allocation and structure offsets may move."""
    ranges = [r for r in layout.executable_file_ranges if r.stop - r.start >= 24]
    read = image.read_u32
    hits = [offset for offset in image.find_masked(_PROC_BEST_NAME_VALUES, _PROC_BEST_NAME_MASKS, ranges)
            if _is_proc_best_name([read(offset + i * 4) for i in range(6)])]
    if len(hits) != 1:
        if not hits:
            raise PatchfinderError.no_candidate('proc_best_name data flow')
        raise PatchfinderError.ambiguous_candidate('proc_best_name data flow', hits)
    return hits[0]


def _is_proc_best_name(words: Sequence[int]) -> bool:
    first_add = _decode_add(words[0])
    byte_load = _decode_byte_load(words[1])
    second_add = _decode_add(words[2])
    compared = _decode_compare_zero(words[3])
    select = _decode_select(words[4])
    if first_add is None or byte_load is None or second_add is None or compared is None or select is None \
            or words[5] != ARM64.ret:
        return False
    return (first_add[1] == byte_load[1]
            and first_add[1] == second_add[1]
            and byte_load[2] == first_add[2]
            and first_add[2] == second_add[2] + 0x11
            and compared == byte_load[0]
            and select[0] == 0
            and select[1] == second_add[0]
            and select[2] == first_add[0]
            and select[3] == 0)                       # EQ: an empty p_name chooses p_comm


def _decode_add(word: int) -> Optional[Tuple[int, int, int]]:
    """ADD Xd,Xn,#imm12 -> (d, n, imm)."""
    if word & 0xFFC0_0000 != 0x9100_0000:
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF


def _decode_byte_load(word: int) -> Optional[Tuple[int, int, int]]:
    """LDRB Wt,[Xn,#imm12] -> (t, n, imm)."""
    if word & 0xFFC0_0000 != 0x3940_0000:
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 10) & 0xFFF


def _decode_compare_zero(word: int) -> Optional[int]:
    """CMP Wn,#0 (SUBS WZR,Wn,#0) -> n."""
    if word & 0xFFFF_FC1F != 0x7100_001F:
        return None
    return (word >> 5) & 0x1F


def _decode_select(word: int) -> Optional[Tuple[int, int, int, int]]:
    """CSEL Xd,Xn,Xm,cond -> (d, n, m, cond)."""
    if word & 0xFFE0_0C00 != 0x9A80_0000:
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F, (word >> 12) & 0xF


# -- executable cave ---------------------------------------------------------------------------------------------

def _resolve_executable_cave(image: core.BinaryImage, layout: core.MachOLayout) -> int:
    """Zero-filled executable padding right after a unique completed-function tail, rejected if any direct branch
    or chained pointer lands in the bytes the shim will occupy."""
    tail = _CAVE_PREDECESSOR.unique_match(image, layout)
    cave = tail + len(_CAVE_PREDECESSOR.values) * 4
    size = len(_SHIM_TEMPLATE) * 4
    cave_range = range(cave, cave + size)
    if not any(r.start <= cave_range.start and r.stop >= cave_range.stop for r in layout.executable_file_ranges):
        raise PatchfinderError.no_candidate('file-backed executable Sandbox cave')
    if image.bytes_at(cave, size).count(0) != size:
        raise PatchfinderError.no_candidate('zero-filled Sandbox cave')

    branches = _direct_branches_into(image, layout.executable_file_ranges, cave_range)
    if branches:
        raise PatchfinderError.invalid_fixture(
            f'direct branch at {hex64(branches[0])} targets the proposed Sandbox cave')
    pointers = _chained_pointers_into(image, cave_range)
    if pointers:
        raise PatchfinderError.invalid_fixture(
            f'chained pointer at {hex64(pointers[0])} targets the proposed Sandbox cave')
    return cave


# Offsets per byte-search window in _direct_branches_into: small enough that one window needs one or two
# displacement-prefix needles, large enough that the Python call overhead stays negligible.
_BRANCH_WINDOW = 0x4000


def _direct_branches_into(image: core.BinaryImage, ranges: Sequence[range], targets: range) -> List[int]:
    """Every 4-aligned offset o (range by range, ascending; o + 4 <= range end) whose word is a B/BL with
    ARM64.direct_branch_target(word, o) in `targets` (file-offset arithmetic).

    For o in a window [base, stop) a hit's imm26 = (t - o) / 4 lies in a known interval, so its top ten bits (word
    bytes 2..3 together with the B/BL opcode) take only one to three values; those two-byte needles are searched
    with bytes.find and every aligned hit is verified with the exact decoder.
    """
    data, read = image.data, image.read_u32
    low, high = targets.start, targets.stop
    hits: List[int] = []
    if low >= high:
        return hits
    for r in ranges:
        first = (r.start + 3) & ~3
        end = min(r.stop, image.count) - 3                # o < end  <=>  o + 4 <= range end
        found: List[int] = []
        base = first
        while base < end:
            stop = min(end, base + _BRANCH_WINDOW)
            imm_low = max((low - stop) >> 2, -(1 << 25))
            imm_high = min((high - base) >> 2, (1 << 25) - 1)
            if imm_low <= imm_high:
                prefixes = {k & 0x3FF for k in range(imm_low >> 16, (imm_high >> 16) + 1)}
                for prefix in prefixes:
                    for opcode in (0x14, 0x94):                   # B, BL
                        needle = bytes((prefix & 0xFF, opcode | (prefix >> 8)))
                        hit = data.find(needle, base + 2, stop + 3)
                        while hit != -1:
                            offset = hit - 2
                            if offset & 3 == 0:
                                target = ARM64.direct_branch_target(read(offset), offset)
                                if target is not None and low <= target < high:
                                    found.append(offset)
                            hit = data.find(needle, hit + 1, stop + 3)
            base = stop
        found.sort()
        hits.extend(found)
    return hits


def _chained_pointers_into(image: core.BinaryImage, targets: range) -> List[int]:
    """Every 8-aligned offset p (p + 8 <= count), ascending, whose qword has a non-zero high word and a low word
    in `targets` (the low word's top three bytes are searched, the low byte and alignment checked per hit)."""
    data, count, read = image.data, image.count, image.read_u32
    low, high = targets.start, targets.stop
    hits: List[int] = []
    if low >= high:
        return hits
    for page in range(low >> 8, ((high - 1) >> 8) + 1):
        if page > 0xFF_FFFF:
            break
        needle = page.to_bytes(3, 'little')
        hit = data.find(needle, 1)
        while hit != -1:
            offset = hit - 1
            if offset & 7 == 0 and offset + 8 <= count and low <= (page << 8 | data[offset]) < high \
                    and read(offset + 4) != 0:
                hits.append(offset)
            hit = data.find(needle, hit + 1)
    hits.sort()
    return hits


def _build_open_shim(cave: int, current_thread_ro: int, proc_best_name: int,
                     vnode_check_open: int) -> List[Tuple[int, str]]:
    shim = list(_SHIM_TEMPLATE)
    for index, target, link in ((_SHIM_BRANCH_CURRENT_THREAD_RO, current_thread_ro, True),
                                (_SHIM_BRANCH_PROC_BEST_NAME, proc_best_name, True),
                                (_SHIM_BRANCH_VNODE_CHECK_OPEN, vnode_check_open, False)):
        instruction_offset = cave + index * 4
        encoded = ARM64.encode_direct_branch(link, instruction_offset, target)
        if encoded is None:
            raise PatchfinderError.no_candidate(
                f'Sandbox shim branch from {hex64(instruction_offset)} to {hex64(target)}')
        shim[index] = (encoded, shim[index][1])
    return shim


# ================================================================================================================
# Code signing (boot-jit; reached through kernel_policy.codesigning_required only when a profile opts in)
# ================================================================================================================

def ppl_allow_invalid(image: core.BinaryImage) -> List[PatchRecord]:
    """Create every pmap allow-invalid (exact 13-word producer signature). Emits
    kernel.codesign.ppl-allow-invalid.{immediate,refcount}."""
    raise NotImplementedError('kernel_cs.ppl_allow_invalid')


# -- vm_fault_enter cs_bypass ------------------------------------------------------------------------------------
#
#     if (cs_bypass) {
#         cs_violation = FALSE;      // tbz wF, #3, else ; mov wV, #0 ; ...
#     } else if (m->vmp_cs_tainted) { ... }
#
# Candidate: `tbz w*, #3` followed by `mov w*, #0` (optionally with one `mov xD, x23`, xD >= 16, in between), and
# the nearest preceding `tbz w16-31, #2` within 0x20 instructions must branch to the candidate or at most two
# instructions before it. Exactly one candidate must exist across the executable ranges.

def _byte_class(predicate) -> bytes:
    return b'[' + b''.join(re.escape(bytes((value,))) for value in range(256) if predicate(value)) + b']'


_MOV_W_ZERO_BYTES = _byte_class(lambda b: b < 0x20) + b'\x00\x80\x52'               # w & 0xFFFFFFE0 == 0x52800000
_MOV_X_X23_BYTES = _byte_class(lambda b: b & 0x10) + b'[\x02\x03]\x17\xaa'          # w & 0xFFFFFE10 == 0xAA170210
# Matches the top byte (0x36) of a TBZ W word and looks ahead at the following word(s); the zero-width lookahead
# keeps overlapping candidates. Byte 2 (bit number 3) and alignment are checked per hit.
_TBZ3_FOLLOWED_BY_ZERO = re.compile(
    b'\x36(?=' + _MOV_W_ZERO_BYTES + b'|' + _MOV_X_X23_BYTES + _MOV_W_ZERO_BYTES + b')', re.DOTALL)


def vm_fault_cs_bypass(image: core.BinaryImage) -> List[PatchRecord]:
    """NOP the unique `tbz w*, #3` cs_bypass test in vm_fault_enter. Emits kernel.codesign.vm-fault-cs-bypass."""
    layout = core.MachOLayout.of(image)
    data = image.data
    candidates: List[int] = []
    for r in layout.executable_file_ranges:
        first = (r.start + 3) & ~3
        for match in _TBZ3_FOLLOWED_BY_ZERO.finditer(data, r.start, min(r.stop, len(data))):
            offset = match.start() - 3
            # tbz w*, #3, <label>: word & 0xFFF80000 == 0x36180000 (byte 3 matched, byte 2 in 0x18..0x1f)
            if offset & 3 or offset < first or not 0x18 <= data[offset + 2] <= 0x1F:
                continue
            if _cs_bypass_guarded(image, offset, r):
                candidates.append(offset)
    if len(candidates) != 1:
        if not candidates:
            raise PatchfinderError.no_candidate('vm_fault_enter cs_bypass test')
        raise PatchfinderError.ambiguous_candidate('vm_fault_enter cs_bypass test', candidates)
    site = candidates[0]
    return [PatchRecord.from_words(
        id='kernel.codesign.vm-fault-cs-bypass',
        component=_COMPONENT,
        offset=site,
        original=image.read_u32(site),
        replacement=ARM64.nop,
        summary='Always take the cs_bypass branch in vm_fault_enter',
        evidence=[
            'tbz w*, #3 followed by mov w*, #0 (cs_violation = FALSE)',
            'nearest preceding tbz w16-31, #2 branches to it',
            'unique match in executable kernel segments',
        ],
    )]


def _cs_bypass_guarded(image: core.BinaryImage, offset: int, r: range) -> bool:
    """The nearest preceding `tbz w16-31, #2` within 0x20 instructions targets offset - 8 .. offset."""
    back = 1
    while back <= 0x20 and offset >= r.start + back * 4:
        at = offset - back * 4
        word = image.read_u32(at)
        if word & 0xFFF8_0010 == 0x3610_0010:
            target = ARM64.test_branch_target(word, at)
            if target is None:
                return False
            return target <= offset and offset - target <= 8
        back += 1
    return False


def vm_map_protect(image: core.BinaryImage) -> List[PatchRecord]:
    """Let vm_map_protect keep execute permission on modified pages. Emits
    kernel.codesign.vm-map-protect.{keep-execute,disallow-new-exec,bit9}."""
    raise NotImplementedError('kernel_cs.vm_map_protect')
