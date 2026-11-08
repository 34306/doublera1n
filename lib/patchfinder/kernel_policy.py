"""Kernel boot-plan policy resolver families: persona / USB boot policy, AKS + SEP silencing, Sandbox MACF hooks,
exception-port enforcement and the code-signing (JIT) patches.

Each public function takes a core.BinaryImage (the decompressed kernelcache) and returns [core.PatchRecord].
PREFIXES maps every function to the record-id prefixes it can emit (used by `resolve.py --only`).

    function               what it does                                              status
    boot_policy            persona uid/gid zero and USB restore-mode forcing         implemented
    aks                    AppleKeyStore anti-hang changes                           implemented
    sep_silence            SEP panic / timeout / power silencing                     implemented
    sep                    aks + sep_silence                                         implemented (composition)
    sandbox                Sandbox MACF hooks, optional scoped vnode-open shim       -> kernel_cs.py
    sandbox_compatibility  sandbox(image, include_scoped_vnode_open=False)           implemented (composition)
    exception_port         clear the exception-port behavior enforcement byte        implemented
    ppl_allow_invalid      pmap allow-invalid                                        -> kernel_cs.py
    vm_fault_cs_bypass     vm_fault_enter cs_bypass test                             -> kernel_cs.py
    vm_map_protect         vm_map_protect keeps execute permission                   -> kernel_cs.py
    codesigning_required   the three code-signing families, if the profile opts in   implemented (profile gate)

Functions marked -> kernel_cs.py live in kernel_cs and are re-exported here, so every kernel boot-plan family can be
addressed through this module.
"""
from __future__ import annotations

from typing import List, NamedTuple, Optional, Tuple

try:
    from . import core                     # imported as a package
    from .kernel_cs import sandbox, ppl_allow_invalid, vm_fault_cs_bypass, vm_map_protect
except ImportError:                        # flat import: the package directory is on sys.path
    import core
    from kernel_cs import sandbox, ppl_allow_invalid, vm_fault_cs_bypass, vm_map_protect

PatchfinderError, PatchRecord = core.PatchfinderError, core.PatchRecord
ARM64, MachOLayout, MaskedInstructionPattern = core.ARM64, core.MachOLayout, core.MaskedInstructionPattern
hex64, only = core.hex64, core.only

CODESIGN_VARIANT_KEY = 'kernel-codesign-invalid'

PREFIXES = {
    'boot_policy': ('kernel.persona.', 'kernel.usb.'),
    'aks': ('kernel.aks.',),
    'sep_silence': ('kernel.sep.',),
    'sep': ('kernel.aks.', 'kernel.sep.'),
    'sandbox': ('kernel.sandbox.',),
    'sandbox_compatibility': ('kernel.sandbox.',),
    'exception_port': ('kernel.exception-port.',),
    'ppl_allow_invalid': ('kernel.codesign.ppl-allow-invalid.',),
    'vm_fault_cs_bypass': ('kernel.codesign.vm-fault-cs-bypass',),
    'vm_map_protect': ('kernel.codesign.vm-map-protect.',),
    'codesigning_required': ('kernel.codesign.',),
}

_RETAB = 0xD65F_0FFF


def _word_patch(image: core.BinaryImage, id: str, offset: int, replacement: int, summary: str,  # noqa: A002
                evidence) -> PatchRecord:
    """One kernelcache instruction replacement; the original word is read from the image."""
    return PatchRecord.from_words(id=id, component='kernelcache', offset=offset, original=image.read_u32(offset),
                                  replacement=replacement, summary=summary, evidence=evidence)


# ----------------------------------------------------------------------------------------------------------------
# boot_policy: spawn_validate_persona UID/GID guards + isDeviceInRestoreMode
# ----------------------------------------------------------------------------------------------------------------

def boot_policy(image: core.BinaryImage) -> List[PatchRecord]:
    """Persona uid/gid zero and USB restore-mode forcing. Emits kernel.persona.{uid-zero,gid-zero} and
    kernel.usb.{restore-mode-result,restore-mode-return}.

    Independent of SEP and MACF: the two persona rejection branches and the USB restore-mode predicate. A restore
    or ramdisk boot already has `rd=md0`, so this family only belongs to the normal-boot plans.
    """
    layout = MachOLayout.of(image)
    return _persona_guards(image, layout) + _restore_mode_stub(image, layout)


class _LoadW(NamedTuple):
    destination: int
    base: int
    byte_offset: int


def _decode_ldr_w_unsigned(instruction: int) -> Optional[_LoadW]:
    """LDR Wt,[Xn,#imm] (unsigned offset)."""
    if instruction & 0xFFC0_0000 != 0xB940_0000:
        return None
    return _LoadW(instruction & 0x1F, (instruction >> 5) & 0x1F, ((instruction >> 10) & 0xFFF) * 4)


def _is_cbz_w(instruction: int, register: int) -> bool:
    return instruction & 0xFF00_001F == 0x3400_0000 | register          # CBZ Wregister,<target>


def _is_adrp_x0(instruction: int) -> bool:
    return instruction & 0x9F00_001F == 0x9000_0000                     # ADRP X0,<page>


def _is_add_x0_x0(instruction: int) -> bool:
    return instruction & 0xFFC0_03FF == 0x9100_0000                     # ADD X0,X0,#imm


# Pre-filter for the persona scan: LDR W,[X,#0x18] ; CBZ W ; LDR W,[X,#8] ; CBZ W ; LDR W,[X,#0xc] ; CBZ W.
# Every word the full check below requires has exactly these opcode/immediate bits, so the masked scan only drops
# offsets that the per-offset checks would reject anyway (registers, targets and the result moves are checked there).
_PERSONA_VALUES = (0xB940_0000 | (0x18 // 4) << 10, 0x3400_0000,
                   0xB940_0000 | (0x08 // 4) << 10, 0x3400_0000,
                   0xB940_0000 | (0x0C // 4) << 10, 0x3400_0000)
_PERSONA_MASKS = (0xFFFF_FC00, 0xFF00_0000, 0xFFFF_FC00, 0xFF00_0000, 0xFFFF_FC00, 0xFF00_0000)


def _persona_guards(image: core.BinaryImage, layout: MachOLayout) -> List[PatchRecord]:
    """The narrow non-root UID/GID rejection at the end of `spawn_validate_persona`.

    Source-level shape:
        load sibling field at +0x18; CBZ continue
        load persona UID at +0x08; CBZ deny
        load persona GID at +0x0c; CBZ deny
        fallthrough: result = 0
        deny:        result = 1
    Both patched branches must test the register just loaded, use the same base object and land on the same
    `mov wN,#1` deny block, so a generic pair of nearby CBZ instructions is never patched.
    """
    read = image.read_u32
    matches: List[Tuple[int, int]] = []
    for offset in image.find_masked(_PERSONA_VALUES, _PERSONA_MASKS, layout.executable_file_ranges):
        sibling_load, sibling_branch = read(offset), read(offset + 4)
        uid_load, uid_branch = read(offset + 8), read(offset + 12)
        gid_load, gid_branch = read(offset + 16), read(offset + 20)

        sibling = _decode_ldr_w_unsigned(sibling_load)
        if sibling is None or sibling.byte_offset != 0x18 or not _is_cbz_w(sibling_branch, sibling.destination):
            continue
        uid = _decode_ldr_w_unsigned(uid_load)
        if uid is None or uid.byte_offset != 0x08:
            continue
        gid = _decode_ldr_w_unsigned(gid_load)
        if gid is None or gid.byte_offset != 0x0C or uid.base != gid.base:
            continue
        if not _is_cbz_w(uid_branch, uid.destination) or not _is_cbz_w(gid_branch, gid.destination):
            continue
        uid_address = layout.virtual_address(offset + 12)
        gid_address = layout.virtual_address(offset + 20)
        if uid_address is None or gid_address is None:
            continue
        uid_target = ARM64.conditional_target(uid_branch, uid_address)
        gid_target = ARM64.conditional_target(gid_branch, gid_address)
        if uid_target is None or gid_target is None or uid_target != gid_target:
            continue
        deny_offset = layout.file_offset(uid_target)
        if deny_offset is None or deny_offset + 4 > image.count:
            continue

        # The fallthrough accepts the request with result zero; the common branch target rejects it with result
        # one. Require the same destination register so the CFG meaning is explicit.
        accept = read(offset + 24)
        deny = read(deny_offset)
        result_register = accept & 0x1F
        if accept & 0xFFFF_FFE0 != 0x5280_0000 or deny != 0x5280_0020 | result_register:   # MOV Wn,#0 / #1
            continue
        matches.append((offset + 12, offset + 20))

    name = 'spawn_validate_persona sibling guards'
    match = only(matches)
    if match is None:
        if not matches:
            raise PatchfinderError.no_candidate(name)
        raise PatchfinderError.ambiguous_candidate(name, [o for pair in matches for o in pair])
    uid_site, gid_site = match
    return [
        _word_patch(image, 'kernel.persona.uid-zero', uid_site, ARM64.nop,
                    'Allow the persona UID override to be zero',
                    ('LDR Wn,[persona,#8] followed by CBZ Wn',
                     'UID and GID branches share the same result-one deny block')),
        _word_patch(image, 'kernel.persona.gid-zero', gid_site, ARM64.nop,
                    'Allow the persona GID override to be zero',
                    ('LDR Wn,[persona,#0xc] followed by CBZ Wn',
                     'fallthrough writes result zero while the shared target writes result one')),
    ]


_RESTORE_CLUSTER_PREFIX = '1211111212221212111111111111111111111'
_RESTORE_CLUSTER = (_RESTORE_CLUSTER_PREFIX + '\0rd\0rootdev\0-restore\0%02X').encode()


def _restore_mode_stub(image: core.BinaryImage, layout: MachOLayout) -> List[PatchRecord]:
    """Locate the restore-mode predicate through the `rd`/`rootdev` boot-arg cluster and its two sibling
    `PE_parse_boot_argn` calls.

    The two letters "rd" alone occur all over the kernelcache; the surrounding string cluster identifies the
    right literal, and the call/data-flow checks pick which of its xrefs is the actual boolean predicate.
    """
    anchor = 'rd/rootdev boot-argument cluster'
    clusters = image.find_all(_RESTORE_CLUSTER)
    cluster_offset = only(clusters)
    if cluster_offset is None:
        if not clusters:
            raise PatchfinderError.missing_anchor(anchor)
        raise PatchfinderError.ambiguous_anchor(anchor, len(clusters))
    rd_offset = cluster_offset + len(_RESTORE_CLUSTER_PREFIX.encode()) + 1
    candidates: List[int] = []

    for reference in layout.adrp_add_references(rd_offset):
        first_call = _parse_boot_argument_call(reference.add_offset, image, layout)
        if first_call is None:
            continue
        function_start = _nearest_function_entry(reference.adrp_offset, 0x100, image, layout)
        if function_start is None or function_start < 4 or image.read_u32(function_start - 4) != _RETAB:
            continue

        # The predicate parses both `rd` and `rootdev` into the same local buffer using the same helper, so a
        # lone boot-arg parser elsewhere in the kernel cannot satisfy this check.
        found_sibling = False
        cursor = first_call + 4
        limit = min(reference.add_offset + 0x40, image.count - 16)
        while cursor <= limit:
            if _is_adrp_x0(image.read_u32(cursor)) and _is_add_x0_x0(image.read_u32(cursor + 4)):
                sibling_call = _parse_boot_argument_call(cursor + 4, image, layout)
                if sibling_call is not None and (_direct_call_target(sibling_call, image, layout)
                                                 == _direct_call_target(first_call, image, layout)):
                    found_sibling = True
                    break
            cursor += 4
        if found_sibling:
            candidates.append(function_start)

    unique_candidates = sorted(set(candidates))
    entry = only(unique_candidates)
    if entry is None:
        if not unique_candidates:
            raise PatchfinderError.no_candidate('isDeviceInRestoreMode')
        raise PatchfinderError.ambiguous_candidate('isDeviceInRestoreMode', unique_candidates)
    # Write from the prologue so a BTI landing pad, when the build has one, stays intact for indirect branches.
    start = ARM64.stub_start(entry, image)
    return [
        _word_patch(image, 'kernel.usb.restore-mode-result', start, ARM64.mov_x0_one,
                    'Report restore mode to the USB Restricted Mode policy',
                    ('unique rd/rootdev/-restore boot-argument string cluster',
                     'function owns sibling rd and rootdev parser calls to the same helper',
                     'arm64e entry follows RETAB')),
        _word_patch(image, 'kernel.usb.restore-mode-return', start + 4, ARM64.ret,
                    'Return the forced restore-mode result', ('paired entry-point stub',)),
    ]


def _parse_boot_argument_call(add_offset: int, image: core.BinaryImage, layout: MachOLayout) -> Optional[int]:
    """Validate `ADD materialized-string; MOV X1,SP; MOV W2,#0x20; BL parser` and return the BL file offset."""
    if (add_offset + 16 > image.count
            or image.read_u32(add_offset + 4) != 0x9100_03E1           # MOV X1,SP
            or image.read_u32(add_offset + 8) != 0x5280_0402           # MOV W2,#0x20
            or _direct_call_target(add_offset + 12, image, layout) is None):
        return None
    return add_offset + 12


def _nearest_function_entry(offset: int, maximum_distance: int, image: core.BinaryImage,
                            layout: MachOLayout) -> Optional[int]:
    """Nearest function entry before the boot-argument xref; None (this xref is skipped, not an error) when the
    xref is not executable or no entry lies within `maximum_distance`.

    This is the address a caller branches to (on a BTI build the `BTI C` pad rather than the PACIBSP), so the
    predecessor test sees the previous function's terminator, not this function's landing pad.
    """
    if not any(offset in r for r in layout.executable_file_ranges):
        return None
    return ARM64.function_start(offset, image, layout, limit=maximum_distance)


def _direct_call_target(offset: int, image: core.BinaryImage, layout: MachOLayout) -> Optional[int]:
    """File offset of a BL's target (virtual-address arithmetic), else None."""
    source_address = layout.virtual_address(offset)
    if source_address is None:
        return None
    target_address = ARM64.branch_link_target(image.read_u32(offset), source_address)
    if target_address is None:
        return None
    return layout.file_offset(target_address)


# ----------------------------------------------------------------------------------------------------------------
# aks / sep_silence: relocation-masked AppleKeyStore and AppleSEPManager signatures
# ----------------------------------------------------------------------------------------------------------------
# Each value tuple is a reference ARM64 instruction sequence. Branch destinations and other build-dependent fields
# are cleared by the paired mask tuple: a 1 bit must match, a 0 bit is ignored. The masks are bitfields, not opcodes.

def _pattern(name: str, values, masks) -> MaskedInstructionPattern:
    return MaskedInstructionPattern(name, values, masks)


# PACIBSP; save X20/X19 and FP/LR; establish FP; MOV X19,X0; LDR X0,[X0,#0x108]; CBZ X0,<target>; BL <target>;
# CBNZ W0,<target>; restore FP/LR and X20/X19; RETAB.
_SEP_PANIC_CHECK = _pattern(
    'sepPanicCheck',
    (0xD503237F, 0xA9BE4FF4, 0xA9017BFD, 0x910043FD, 0xAA0003F3, 0xF9408400, 0xB4000000, 0x94000000, 0x35000000,
     0xA9417BFD, 0xA8C24FF4, 0xD65F0FFF),
    (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF00001F, 0xFC000000, 0xFF00001F,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF))

# PACIBSP; allocate 0x30-byte frame; save X20/X19 and FP/LR; establish FP; MOV X8,X0; LDR W9,[X8,#0xdc]!;
# SUB W10,W9,#7.
_DID_TIMEOUT = _pattern(
    'AppleSEPManager::_didTimeout',
    (0xD503237F, 0xD100C3FF, 0xA9014FF4, 0xA9027BFD, 0x910083FD, 0xAA0003E8, 0xB84DCD09, 0x51001D2A),
    (0xFFFFFFFF,) * 8)

# BLRAA X8,X16; LDRH W8,[X19,#0xf0]; TBNZ W8,#4,<target>; LDR X0,[X19,#0xd8]; CBZ X0,<target>; BL <target>;
# LDRH W8,[X19,#0xf0]; ORR W9,W8,#0x10.
_AKS_START_CALL = _pattern(
    'AKSUserClient::start SEP call',
    (0xD73F0910, 0x7941E268, 0x37200008, 0xF9406E60, 0xB4000000, 0x94000000, 0x7941E268, 0x321C0109),
    (0xFFFFFFFF, 0xFFFFFFFF, 0xFFF8001F, 0xFFFFFFFF, 0xFF00001F, 0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF))

# PACIBSP; allocate 0x1a0-byte frame; save X28..X19 and FP/LR; establish FP; MOV X21,X2; MOV X20,X1; MOV X22,X0.
_EXTERNAL_METHOD = _pattern(
    'AKSUserClient::externalMethod',
    (0xD503237F, 0xD10683FF, 0xA9146FFC, 0xA91567FA, 0xA9165FF8, 0xA91757F6, 0xA9184FF4, 0xA9197BFD, 0x910643FD,
     0xAA0203F5, 0xAA0103F4, 0xAA0003F6),
    (0xFFFFFFFF,) * 12)

# BL <target>; LDR W8,[X25]; TST W8,#0xfffffff7; B.EQ <target>; BL <target>; SXTW X3,W0; MOV X8,X21; SXTW X4,W8.
_EXTERNAL_METHOD_LOG = _pattern(
    'AKSUserClient::externalMethod IOLog call',
    (0x94000000, 0xB9400328, 0x721C791F, 0x54000000, 0x94000000, 0x93407C03, 0xAA1503E8, 0x93407D04),
    (0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF00001F, 0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF))

# CBZ X0,<target>; LDRB W8,[X19,#0xcc]; TBZ W8,#0,<target>; MOV X0,X19; MOV W1,#15000; BL <target>;
# BL <target>; LDRB W8,[X19,#0xa5a].
_SET_POWER_A = _pattern(
    'AppleSEPManager::_setPowerState first failure gate',
    (0xB4000000, 0x39433268, 0x36000008, 0xAA1303E0, 0x52875301, 0x94000000, 0x94000000, 0x39696A68),
    (0xFF00001F, 0xFFFFFFFF, 0xFFF8001F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000, 0xFC000000, 0xFFFFFFFF))

# CBZ X0,<target>; MOV X0,X20; MOV W1,#15000; BL <target>; BL <target>; LDR W8,[X20,#0xc8]; CMP W8,#2;
# B.NE <target>.
_NOTIFY_ACTIVE = _pattern(
    'AppleSEPManager::_notifyOSActiveGated failure gate',
    (0xB4000000, 0xAA1403E0, 0x52875301, 0x94000000, 0x94000000, 0xB940CA88, 0x7100091F, 0x54000001),
    (0xFF00001F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000, 0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFF00001F))

# CBZ X0,<target>; MOV X0,X19; MOV W1,#15000; BL <target>; CBZ X0,<target>; MOV X0,X19; MOV W1,#1; BL <target>.
_SET_POWER_B = _pattern(
    'AppleSEPManager::_setPowerState second failure gate',
    (0xB4000000, 0xAA1303E0, 0x52875301, 0x94000000, 0xB4000000, 0xAA1303E0, 0x52800021, 0x94000000),
    (0xFF00001F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000, 0xFF00001F, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000))

# B.EQ <target>; MOV W0,#1000; BL <target>; ADD W21,W21,#1; MOV X0,X19; BL <target>; TBZ W0,#0,<target>;
# LDP FP,LR,[SP,#0x30].
_PRNG_RESEED = _pattern(
    'AppleSEPManager PRNG reseed failure gate',
    (0x54000000, 0x52807D00, 0x94000000, 0x110006B5, 0xAA1303E0, 0x94000000, 0x36000000, 0xA9437BFD),
    (0xFF00001F, 0xFFFFFFFF, 0xFC000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFC000000, 0xFFF8001F, 0xFFFFFFFF))

# The selector-7 shim written after the entry PACIBSP of AKSUserClient::externalMethod. The PACIBSP at +0 stays:
# indirect virtual dispatch may land there, and both exits use RETAB, so it must keep signing the return address.
# It writes a coherent `noPin | beenUnlocked` state instead of returning success with an untouched output buffer.
_SELECTOR7_SHIM: Tuple[Tuple[int, str], ...] = (
    (0x7100_1C3F, 'CMP W1,#7 - recognize selector 7'),
    (0x5400_01C1, 'B.NE success - other selectors keep the existing success path'),
    (0xB400_01E2, 'CBZ X2,badArgument - reject a null arguments pointer'),
    (0xF940_1048, 'LDR X8,[X2,#0x20] - load scalarInput'),
    (0xB400_01A8, 'CBZ X8,badArgument - reject a null scalarInput'),
    (0xB940_2848, 'LDR W8,[X2,#0x28] - load scalarInputCount'),
    (0x7100_051F, 'CMP W8,#1 - require one scalar input'),
    (0x5400_0141, 'B.NE badArgument - reject an input-count mismatch'),
    (0xF940_2449, 'LDR X9,[X2,#0x48] - load scalarOutput'),
    (0xB400_0109, 'CBZ X9,badArgument - reject a null scalarOutput'),
    (0xB940_5048, 'LDR W8,[X2,#0x50] - load scalarOutputCount'),
    (0x7100_051F, 'CMP W8,#1 - require one scalar output'),
    (0x5400_00A1, 'B.NE badArgument - reject an output-count mismatch'),
    (0xD280_00C8, 'MOV X8,#6 - synthesize noPin plus beenUnlocked'),
    (0xF900_0128, 'STR X8,[X9] - write the synthesized scalar output'),
    (0xD280_0000, 'MOV X0,#0 - return KERN_SUCCESS'),
    (0xD65F_0FFF, 'RETAB - authenticated return from the success path'),
    (0x5280_5840, 'MOV W0,#0x2c2 - low half of kIOReturnBadArgument'),
    (0x72BC_0000, 'MOVK W0,#0xe000,LSL#16 - finish kIOReturnBadArgument'),
    (0xD65F_0FFF, 'RETAB - authenticated return from the rejection path'),
)


def aks(image: core.BinaryImage) -> List[PatchRecord]:
    """AppleKeyStore anti-hang changes. Emits kernel.aks.start.sep-call, kernel.aks.external-method.selector7.<n>,
    kernel.aks.external-method.log-call.

    The 22 records shared by normal and diagnostic kernels: they keep a dead SEP from leaving keybag
    initialization stuck.
    """
    layout = MachOLayout.of(image)
    start_call = _AKS_START_CALL.unique_match(image, layout)
    external_method = _EXTERNAL_METHOD.unique_match(image, layout)
    log_call = _EXTERNAL_METHOD_LOG.unique_match(image, layout)

    patches = [
        _word_patch(image, 'kernel.aks.start.sep-call', start_call, ARM64.nop,
                    'Skip the SEP-dependent call in AKSUserClient::start',
                    ('unique relocation-masked AKS start-call body',)),
    ]
    for index, (word, description) in enumerate(_SELECTOR7_SHIM):
        patches.append(_word_patch(
            image, f'kernel.aks.external-method.selector7.{index}', external_method + 4 + index * 4, word,
            f'Selector-7 shim: {description}',
            ('unique relocation-masked AKSUserClient::externalMethod prologue',
             'IOExternalMethodArguments LP64 offsets validated by the native selector-7 path',
             'entry PACIBSP is deliberately preserved')))
    patches.append(_word_patch(
        image, 'kernel.aks.external-method.log-call', log_call, ARM64.nop,
        'Silence the now-unreachable externalMethod IOLog call',
        ('unique relocation-masked IOLog call sequence in the AKS external method',)))
    return patches


def sep_silence(image: core.BinaryImage) -> List[PatchRecord]:
    """SEP panic/timeout/power silencing. Emits kernel.sep.* (panic-check, did-timeout, power-notification,
    set-power-a/b, notify-active, prng-reseed).

    The ten normal-boot-only records. Diagnostic kernels omit them so an unhandled SEP failure can still panic and
    leave a useful crash report.
    """
    layout = MachOLayout.of(image)
    panic_check = _SEP_PANIC_CHECK.unique_match(image, layout)
    did_timeout = _DID_TIMEOUT.unique_match(image, layout)
    power_notification = _power_change_notification(image, layout)
    set_power_a = _SET_POWER_A.unique_match(image, layout)
    notify_active = _NOTIFY_ACTIVE.unique_match(image, layout)
    set_power_b = _SET_POWER_B.unique_match(image, layout)
    reseed = _PRNG_RESEED.unique_match(image, layout)

    patches: List[PatchRecord] = []
    for name, start, summary in (
        ('panic-check', panic_check, 'Return success from sepPanicCheck'),
        ('did-timeout', did_timeout, 'Report that the SEP command did not time out'),
        ('power-notification', power_notification, 'Return success from the paging-off notification handler'),
    ):
        patches.append(_word_patch(image, f'kernel.sep.{name}.result', start, ARM64.mov_x0_zero, summary,
                                   ('semantic SEP function entry resolved without a target offset',)))
        patches.append(_word_patch(image, f'kernel.sep.{name}.return', start + 4, ARM64.ret,
                                   'Return the forced SEP result', ('paired entry-point stub',)))
    for name, offset, summary in (
        ('set-power-a', set_power_a, 'Do not enter the first setPowerState SEP failure path'),
        ('notify-active', notify_active, 'Do not enter the notifyOSActiveGated SEP failure path'),
        ('set-power-b', set_power_b, 'Do not enter the second setPowerState SEP failure path'),
        ('prng-reseed', reseed, 'Do not enter the PRNG reseed failure path'),
    ):
        patches.append(_word_patch(image, f'kernel.sep.{name}', offset, ARM64.nop, summary,
                                   ('unique relocation-masked local failure-path sequence',)))
    return patches


_PAGING_OFF_PHRASE = 'AppleSEPManager: Received Paging off notification'


def _power_change_notification(image: core.BinaryImage, layout: MachOLayout) -> int:
    """The paging-off notification handler's PACIBSP.

    Its stack frame changes between builds, so a masked signature would (correctly) refuse it; the diagnostic
    literal is a much stronger anchor with exactly one executable reference. The result is the PACIBSP itself
    (not a preceding BTI pad).
    """
    phrase = _PAGING_OFF_PHRASE
    strings = image.find_all_utf8(phrase)
    string_offset = only(strings)
    if string_offset is None:
        if not strings:
            raise PatchfinderError.missing_anchor(phrase)
        raise PatchfinderError.ambiguous_anchor(phrase, len(strings))
    references = layout.adrp_add_references(string_offset)
    reference = only(references)
    if reference is None:
        if not references:
            raise PatchfinderError.no_candidate('SEP paging-off diagnostic xref')
        raise PatchfinderError.ambiguous_candidate('SEP paging-off diagnostic xref',
                                                   [r.adrp_offset for r in references])
    adrp = reference.adrp_offset
    containing = next((r for r in layout.executable_file_ranges if adrp in r), None)
    if containing is None:
        raise PatchfinderError.no_candidate('SEP paging-off executable range')
    floor = max(containing.start, adrp - min(0x4000, adrp - containing.start))
    cursor = adrp & ~3
    while cursor >= floor + 4:
        if image.read_u32(cursor) == ARM64.pacibsp:
            return cursor
        cursor -= 4
    raise PatchfinderError.no_candidate('SEP paging-off containing function')


# ----------------------------------------------------------------------------------------------------------------
# exception_port: the exception-port behavior enforcement byte
# ----------------------------------------------------------------------------------------------------------------
# XNU's set_exception_behavior_allowed (osfmk/kern/ipc_tt.c) requires tasks with an enhanced IPC space policy, which
# includes every platform binary, to register exception ports with EXCEPTION_STATE or an identity-protected
# behavior. Anything else raises EXC_GUARD flavor 6 (kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE) and returns KERN_DENIED
# while the byte `thid_should_crash` is set. Once the trust-cache patches make every binary a platform binary, apps
# whose crash SDK registers EXCEPTION_DEFAULT die at launch; with the byte clear the violation is ignored and the
# handler is registered normally.
#
# The byte was a boot-arg tunable in xnu-12377; 27.x kernels no longer carry the boot-arg string, so it is patched in
# the image. It lives in __DATA_CONST, holds 1, and no instruction writes it. It is found from the policy function,
# the only code referencing `com.apple.security.only-one-exception-port`:
#   - every ADRP+LDRB in that function loads the same byte;
#   - one load is followed directly by TBZ/TBNZ on the loaded register, and the function's only `MOV W2,#6 ; BL`
#     (the guard call) is on that path;
#   - `SBFX Wd,Wt,#0,#1 ; MOV Wx,#0x35 ; AND` turns the byte into the KERN_DENIED result.

_EXCEPTION_PORT_NAME = 'kernel-exception-port'
_EXCEPTION_PORT_ANCHOR = 'com.apple.security.only-one-exception-port'
_MOV_W2_FLAVOR6 = 0x5280_00C2          # MOVZ W2,#6: the guard flavor argument


class _ByteLoad(NamedTuple):
    offset: int       # the LDRB
    target: int       # file offset of the loaded byte
    rt: int


def exception_port(image: core.BinaryImage) -> List[PatchRecord]:
    """Clear the exception-port behavior enforcement byte in __DATA_CONST.
    Emits kernel.exception-port.behavior-enforcement."""
    name, anchor_text = _EXCEPTION_PORT_NAME, _EXCEPTION_PORT_ANCHOR
    layout = MachOLayout.of(image)
    anchors = image.find_all(b'\0' + anchor_text.encode() + b'\0')
    anchor = only(anchors)
    if anchor is None:
        if not anchors:
            raise PatchfinderError.missing_anchor(anchor_text)
        raise PatchfinderError.ambiguous_anchor(anchor_text, len(anchors))
    refs = layout.adrp_add_references(anchor + 1)
    ref = only(refs)
    if ref is None:
        if not refs:
            raise PatchfinderError.missing_anchor(f'{name} {anchor_text} reference')
        raise PatchfinderError.ambiguous_anchor(f'{name} {anchor_text} reference', len(refs))
    start = ARM64.function_start(ref.adrp_offset, image, layout)
    if start is None:
        raise PatchfinderError.no_candidate(f'{name} policy function')
    end = ARM64.next_function_start(start, image, layout)

    loads: List[_ByteLoad] = []
    guard_calls: List[int] = []
    cursor = start
    while cursor + 8 <= end:
        word = image.read_u32(cursor)
        following = image.read_u32(cursor + 4)
        load = _byte_load(word, cursor, following, layout)
        if load is not None:
            loads.append(_ByteLoad(cursor + 4, load[0], load[1]))
        if word == _MOV_W2_FLAVOR6 and ARM64.branch_link_target(following, cursor + 4) is not None:
            guard_calls.append(cursor)
        cursor += 4

    targets = {load.target for load in loads}
    byte = only(targets)
    if byte is None:
        if not targets:
            raise PatchfinderError.no_candidate(f'{name} enforcement byte load')
        raise PatchfinderError.ambiguous_candidate(f'{name} enforcement byte', sorted(targets))
    guard_call = only(guard_calls)
    if guard_call is None:
        if not guard_calls:
            raise PatchfinderError.no_candidate(f'{name} flavor-6 guard call')
        raise PatchfinderError.ambiguous_candidate(f'{name} flavor-6 guard call', guard_calls)
    if not any(_gates(load, guard_call, image) for load in loads):
        raise PatchfinderError.no_candidate(
            f'{name} byte test whose bypass derives KERN_DENIED and skips the guard call')
    segment = next((s for s in layout.segments if byte in s.file_range), None)
    if segment is None or segment.name != '__DATA_CONST' or segment.is_executable:
        raise PatchfinderError.invalid_patch(name, f'enforcement byte {hex64(byte)} is not in __DATA_CONST')
    # Stock is 1. 0 is this patch already applied; the record still names 1 as the original so the guarded
    # applier reports it as already applied.
    current = image.bytes_at(byte, 1)
    if current not in (b'\x01', b'\x00'):
        raise PatchfinderError.invalid_patch(name, f'enforcement byte {hex64(byte)} is {current[0]:02x}, expected 01')

    return [
        PatchRecord(
            id='kernel.exception-port.behavior-enforcement',
            component='kernelcache',
            offset=byte,
            original_bytes=b'\x01',
            replacement_bytes=b'\x00',
            summary='Ignore non-identity-protected exception-port registrations instead of killing the caller',
            evidence=(
                f'only function referencing {anchor_text}: {hex64(start)}',
                f'all {len(loads)} ADRP+LDRB loads in it read {hex64(byte)} (__DATA_CONST, value 1)',
                f'a load of it is tested by TBZ/TBNZ #0: one edge reaches MOV W2,#6 ; BL at {hex64(guard_call)}',
                'the other edge skips that call and turns the loaded register into KERN_DENIED '
                '(SBFX/MOV #0x35/AND W0)',
            ),
        ),
    ]


def _byte_load(adrp: int, offset: int, following: int, layout: MachOLayout) -> Optional[Tuple[int, int]]:
    """ADRP Xd,page followed by LDRB Wt,[Xd,#imm] (unsigned offset): (file offset of the byte, Rt). The page is
    computed in virtual addresses so code and data segments may slide differently."""
    if (adrp & 0x9F00_0000 != 0x9000_0000
            or following & 0xFFC0_0000 != 0x3940_0000
            or (following >> 5) & 0x1F != adrp & 0x1F):
        return None
    pc = layout.virtual_address(offset)
    if pc is None:
        return None
    address = (ARM64.adrp_target(adrp, pc) + ((following >> 10) & 0xFFF)) & core.MASK64
    target = layout.file_offset(address)
    if target is None:
        return None
    return target, following & 0x1F


def _gates(load: _ByteLoad, guard_call: int, image: core.BinaryImage) -> bool:
    """The word after the load is TBZ/TBNZ Wt,#0 on the loaded register. One edge reaches the guard call (TBZ falls
    through into it, TBNZ branches to it, allowing the two argument moves before `MOV W2,#6`). The other edge, taken
    when the byte is clear, must reach `B` without the guard call and on the way compute the result from the same
    register: `SBFX Wd,Wt,#0,#1`, `MOVZ Wm,#0x35`, `AND W0,Wd,Wm` (either operand order)."""
    test_site = load.offset + 4
    test = image.read_u32(test_site)
    # TBZ is 0x36000000, TBNZ 0x37000000; b5 and b40 zero select bit 0 of W.
    if test & 0xFEF8_0000 != 0x3600_0000 or test & 0x1F != load.rt:
        return False
    target = ARM64.test_branch_target(test, test_site)
    if target is None:
        return False
    is_tbnz = test & 0x0100_0000 != 0
    guard_edge = target if is_tbnz else test_site + 4
    bypass_edge = test_site + 4 if is_tbnz else target
    if guard_call < guard_edge or guard_call - guard_edge > 8:
        return False
    guard_path = range(guard_edge, guard_call + 8)       # the guarded edge through MOV W2,#6 and its BL
    return _bypass_denies_from_byte(bypass_edge, load.rt, guard_path, image)


def _bypass_denies_from_byte(start: int, register: int, guard_path: range, image: core.BinaryImage) -> bool:
    """Straight-line walk of at most eight steps from `start`, ending at a `B` whose target returns."""
    derived = False
    cursor = start
    for _ in range(8):
        if cursor in guard_path:
            return False
        word = image.read_u32(cursor)
        # B (unconditional): the path leaves, and must leave the function.
        if word & 0xFC00_0000 == 0x1400_0000:
            target = ARM64.direct_branch_target(word, cursor)
            if target is None:
                return False
            return derived and _returns(target, guard_path, image)
        # SBFX Wd,Wn,#0,#1 is SBFM Wd,Wn,#0,#0: 0x13000000 | Rn<<5 | Rd.
        if not derived and word & 0xFFFF_FC00 == 0x1300_0000 and (word >> 5) & 0x1F == register:
            sbfx_rd = word & 0x1F
            mov = image.read_u32(cursor + 4)
            and_ = image.read_u32(cursor + 8)
            # MOVZ Wm,#0x35 is 0x528006A0 | Rd. AND Wd,Wn,Wm (shifted register, LSL #0) is
            # 0x0A000000 | Rm<<16 | Rn<<5 | Rd.
            if mov & 0xFFFF_FFE0 != 0x5280_06A0 or and_ & 0xFFE0_FC00 != 0x0A00_0000 or and_ & 0x1F != 0:
                return False
            if {(and_ >> 16) & 0x1F, (and_ >> 5) & 0x1F} != {sbfx_rd, mov & 0x1F}:
                return False
            derived = True
            cursor += 12
            continue
        # Before the SBFX, anything that could overwrite the loaded register breaks the data flow. Branches that
        # only test registers are fine.
        is_test_branch = word & 0x7E00_0000 == 0x3400_0000 or word & 0x7E00_0000 == 0x3600_0000
        if not derived and not is_test_branch and word & 0x1F == register:
            return False
        cursor += 4
    return False


def _returns(start: int, guard_path: range, image: core.BinaryImage) -> bool:
    """The exit target is the function epilogue: straight-line code (register restores, AUTIBSP) reaching
    RET/RETAA/RETAB within twelve words, with no branch and nothing inside the guard path. A self-branch or a jump
    into the guard's BL fails here."""
    cursor = start
    for _ in range(12):
        if cursor in guard_path:
            return False
        word = image.read_u32(cursor)
        if ARM64.is_return(word):
            return True
        # Any other branch: B/BL (0x14/0x94), B.cond (0x54, bit 4 clear), CBZ/CBNZ/TBZ/TBNZ (0x34-0x37) and
        # register branches (0xD6).
        is_branch = (word & 0x7C00_0000 == 0x1400_0000
                     or word & 0xFF00_0010 == 0x5400_0000
                     or word & 0x7C00_0000 == 0x3400_0000
                     or word & 0xFE00_0000 == 0xD600_0000)
        if is_branch:
            return False
        cursor += 4
    return False


# ----------------------------------------------------------------------------------------------------------------
# Compositions and profile gates
# ----------------------------------------------------------------------------------------------------------------

def sep(image: core.BinaryImage) -> List[PatchRecord]:
    """The normal-boot SEP plan: AKS records followed by the SEP silencing records."""
    return aks(image) + sep_silence(image)


def sandbox_compatibility(image: core.BinaryImage) -> List[PatchRecord]:
    """The boot plans' Sandbox step: the established MACF stubs without the scoped vnode-open shim."""
    return sandbox(image, include_scoped_vnode_open=False)


def codesigning_required(image: core.BinaryImage) -> List[PatchRecord]:
    """The boot-jit code-signing step: nothing unless the detected kernel profile opts in to
    'kernel-codesign-invalid'; then ppl_allow_invalid + vm_fault_cs_bypass + vm_map_protect."""
    profile = core.detect_kernel_profile(image)
    if profile is None or profile.variants(CODESIGN_VARIANT_KEY) is None:
        return []
    return ppl_allow_invalid(image) + vm_fault_cs_bypass(image) + vm_map_protect(image)
