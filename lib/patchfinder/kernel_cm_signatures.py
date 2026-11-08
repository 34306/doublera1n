"""Recorded AppleSEPCredentialManager method shapes for kernel_cm.credential_manager, one family per build line.

Each entry is (method name, reference words, needs_scoring). The words are locator evidence recorded from the
build named in the family, in instruction order; they are never written. kernel_cm turns them into
core.MaskedInstructionPattern.from_reference_words(..., allow_data_layout_drift=True), which relaxes branch
displacements, ADRP pages, literal offsets, unsigned load/store immediates and ADD immediates, so the shapes
match a relinked build. The "recorded at" comments are where the words were captured, for review only; the
resolver never uses them.

Entries are in class order: the resolver requires the resolved entries to increase strictly in this order, and a
needs_scoring entry is located between its already-resolved neighbours by 32-word similarity.

A family is selected by the detected kernel profile (core.KERNEL_RESOLVER_PROFILES, variant
'kernel-credential-manager'). Families are kept separate per build line on purpose: sharing one family across
builds would let one build's shapes stand in for another's behind the masks.
"""
from __future__ import annotations

from typing import Dict, NamedTuple, Tuple


class Signature(NamedTuple):
    name: str                    # method name as it appears in record summaries
    words: str                   # whitespace-separated hex instruction words
    needs_scoring: bool = False  # located by neighbour-bounded similarity instead of a unique exact match


VARIANTS: Dict[str, Tuple[Signature, ...]] = {}

# ------------------------------------------------------------------------------------------------------------------
# iOS 27 beta 2 / beta 4 (pre-BTI kernelcaches). Both betas share this family because masked matching
# proved their method shapes compatible. Four bodies drifted between the two betas and are scored
# between their exact neighbours instead of matched exactly.
VARIANTS['ios27-early-beta-acm-v1'] = (
    # pacibsp; sub sp, sp, #64; stp x29, x30, [sp, #48]; add x29, sp, #48; ldr x0, [x0, #152]
    #   ldr x16, [x0]; mov x17, x0; movk x17, #52641, lsl #48; autda x16, x17; ldr x9, [x16, #232]!
    #   mov x8, x16; adrp x16, #20480
    Signature('sepManagerMatchedThreadCallHandler',
              'd503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 '
              'b0000030'),
    # pacibsp; sub sp, sp, #96; stp x29, x30, [sp, #80]; add x29, sp, #80; cbz x4, #52; ldr w8, [x4]
    #   stur w8, [x29, #-32]; ldr x8, [x4, #8]; stur x8, [x29, #-28]; sturb wzr, [x29, #-20]
    #   stur xzr, [x29, #-11]; stur xzr, [x29, #-19]; sub x4, x29, #32; bl #216
    #   ldp x29, x30, [sp, #80]; add sp, sp, #96
    Signature('callPlatformFunction',
              'd503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf '
              'f81ed3bf d10083a4 94000036 a9457bfd 910183ff'),
    # pacibsp; sub sp, sp, #96; stp x29, x30, [sp, #80]; add x29, sp, #80; cbz x4, #56; ldr w8, [x4]
    #   stur w8, [x29, #-32]; ldur x8, [x4, #4]; stur x8, [x29, #-28]; ldrb w8, [x4, #12]
    #   sturb w8, [x29, #-20]; stur xzr, [x29, #-11]; stur xzr, [x29, #-19]; sub x4, x29, #32; bl #80
    #   ldp x29, x30, [sp, #80]
    Signature('cmdContextV2',
              'd503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 '
              'f81f53bf f81ed3bf d10083a4 94000014 a9457bfd'),
    # pacibsp; sub sp, sp, #144; stp x24, x23, [sp, #80]; stp x22, x21, [sp, #96]
    #   stp x20, x19, [sp, #112]; stp x29, x30, [sp, #128]; add x29, sp, #128; cbz x4, #172
    #   mov x23, x4; mov x19, x3; mov x20, x2; mov x21, x1; mov x22, x0; bl #-76632; mov x24, x0
    #   ldrb w1, [x23, #12]
    Signature('cmdContextV3',
              'd503237f d10243ff a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd b4000564 aa0403f7 aa0303f3 aa0203f4 '
              'aa0103f5 aa0003f6 97ffb52a aa0003f8 394032e1'),
    # pacibsp; sub sp, sp, #336; stp x28, x27, [sp, #240]; stp x26, x25, [sp, #256]
    #   stp x24, x23, [sp, #272]; stp x22, x21, [sp, #288]; stp x20, x19, [sp, #304]
    #   stp x29, x30, [sp, #320]; add x29, sp, #320; mov x27, x4; mov x21, x3; mov x25, x2; mov x28, x1
    #   mov x22, x0; movi v0.2d, #0000000000000000; stp q0, q0, [x29, #-128]
    Signature('performCommandGated',
              'd503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403fb aa0303f5 '
              'aa0203f9 aa0103fc aa0003f6 6f00e400 ad3c03a0'),
    # pacibsp; sub sp, sp, #144; stp x28, x27, [sp, #48]; stp x26, x25, [sp, #64]
    #   stp x24, x23, [sp, #80]; stp x22, x21, [sp, #96]; stp x20, x19, [sp, #112]
    #   stp x29, x30, [sp, #128]; add x29, sp, #128; mov x21, x5; mov x22, x4; mov x23, x3; mov x24, x2
    #   mov x20, x1; mov x19, x0; adrp x26, #31965184
    Signature('_performKernelControl',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 '
              'aa0303f7 aa0203f8 aa0103f4 aa0003f3 9000f3fa'),
    # pacibsp; sub sp, sp, #176; stp x28, x27, [sp, #80]; stp x26, x25, [sp, #96]
    #   stp x24, x23, [sp, #112]; stp x22, x21, [sp, #128]; stp x20, x19, [sp, #144]
    #   stp x29, x30, [sp, #160]; add x29, sp, #160; mov x24, x6; mov x25, x5; mov x20, x4; mov x23, x3
    #   mov x19, x2; mov x21, x1; mov x22, x0
    Signature('_performCommand',
              'd503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 '
              'aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6'),
    # pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
    #   stp x29, x30, [sp, #80]; add x29, sp, #80; mov x20, x1; mov x19, x0; adrp x21, #31965184
    #   ldrb w8, [x21, #2600]; cmp w8, #10; b.hi #92; ldrb w8, [x19, #140]; tbz w8, #0, #52
    #   ldr x16, [x19]; mov x17, x19
    Signature('processSCRDResponsePayload',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f3f5 3968a2a8 7100291f '
              '540002e8 39423268 360001a8 f9400270 aa1303f1'),
    # pacibsp; sub sp, sp, #80; stp x20, x19, [sp, #48]; stp x29, x30, [sp, #64]; add x29, sp, #64
    #   mov x19, x0; mov w1, #0; bl #15120; ldr x0, [x19, #280]; ldr x16, [x0]; mov x17, x0
    #   movk x17, #52641, lsl #48; autda x16, x17; ldr x8, [x16, #176]!; movk x16, #39702, lsl #48
    #   blraa x8, x16
    Signature('scheduleDblClickDeferredAck',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000ec4 f9408e60 f9400010 aa0003f1 '
              'f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910'),

    # These bodies retain strong similarity across beta 2 and beta 4,
    # but not an honest exact signature. Neighboring exact functions
    # bound the search before the resolver scores their first 32 words.
    # pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
    #   stp x29, x30, [sp, #80]; add x29, sp, #80; mov x20, x1; mov x19, x0; adrp x22, #31961088
    #   ldrb w8, [x22, #2600]; adrp x21, #-27676672; add x21, x21, #1671; cmp w8, #10; b.hi #84
    #   ldrb w8, [x19, #140]; tbz w8, #0, #52; ldr x16, [x19]; mov x17, x19; movk x17, #52641, lsl #48
    #   autda x16, x17; mov x17, #488; add x16, x16, x17; ldr x8, [x16]; mov x0, x19; mov x1, #0
    #   movk x16, #3228, lsl #48; blraa x8, x16; b #12; adrp x0, #-27680768; add x0, x0, #1331
    #   stp x0, x21, [sp]; adrp x0, #-27746304
    Signature('updateAnalytics',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 f000f3d6 3968a2c8 f0ff2cd5 '
              '911a1eb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 d0ff2cc0 9114cc00 a90057e0 d0ff2c40', True),
    # pacibsp; sub sp, sp, #128; stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]
    #   stp x29, x30, [sp, #112]; add x29, sp, #112; mov x19, x0; adrp x20, #31961088
    #   ldrb w8, [x20, #2600]; cmp w8, #10; b.hi #92; ldrb w8, [x19, #140]; tbz w8, #0, #52
    #   ldr x16, [x19]; mov x17, x19; movk x17, #52641, lsl #48
    Signature('performSCRDInitialization',
              'd503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 f000f3d4 3968a288 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431'),
    # pacibsp; sub sp, sp, #272; stp x28, x27, [sp, #176]; stp x26, x25, [sp, #192]
    #   stp x24, x23, [sp, #208]; stp x22, x21, [sp, #224]; stp x20, x19, [sp, #240]
    #   stp x29, x30, [sp, #256]; add x29, sp, #256; mov x28, x7; str x6, [sp, #104]; mov x22, x5
    #   mov x21, x4; mov x24, x3; mov x25, x2; mov x20, x1; mov x19, x0; stur x4, [x29, #-96]
    #   adrp x8, #31961088; ldrb w8, [x8, #2600]; cmp w8, #10; b.hi #92; ldrb w8, [x19, #140]
    #   tbz w8, #0, #52; ldr x16, [x19]; mov x17, x19; movk x17, #52641, lsl #48; autda x16, x17
    #   mov x17, #488; add x16, x16, x17; ldr x8, [x16]; mov x0, x19
    Signature('sendSEPCommand',
              'd503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc f90037e6 '
              'aa0503f6 aa0403f5 aa0303f8 aa0203f9 aa0103f4 aa0003f3 f81a03a4 f000f3c8 3968a108 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0', True),
    # pacibsp; sub sp, sp, #128; stp x26, x25, [sp, #48]; stp x24, x23, [sp, #64]
    #   stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]; stp x29, x30, [sp, #112]; add x29, sp, #112
    #   mov x19, x1; mov x20, x0; adrp x8, #-19030016; ldr x8, [x8, #3704]; ldr x1, [x8]; mov x0, x19
    #   bl #62088; cbz x0, #712
    Signature('_setPropertiesGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 d0ff6ec8 '
              'f9473d08 f9400101 aa1303e0 94003ca2 b4001640'),
    # pacibsp; sub sp, sp, #80; stp x20, x19, [sp, #48]; stp x29, x30, [sp, #64]; add x29, sp, #64
    #   cbz x1, #76; mov x19, x1; stp xzr, xzr, [sp]; mov w1, #2; mov w2, #0; mov x3, #0; mov x4, #0
    #   mov x5, #0; mov x6, #0; mov w7, #1; bl #-3700
    Signature('performDoubleClickQueryGated',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 '
              'd2800004 d2800005 d2800006 52800027 97fffc63'),
    # bti c; cbz x1, #24; mov w0, #0; adrp x8, #31956992; ldrb w8, [x8, #2600]; str x8, [x1]; ret
    #   pacibsp; sub sp, sp, #64; stp x29, x30, [sp, #48]
    Signature('performLoggingLevelQueryGated',
              'd503245f b40000c1 52800000 d000f3c8 3968a108 f9000028 d65f03c0 d503237f d10103ff a9037bfd'),
    # pacibsp; sub sp, sp, #112; stp x24, x23, [sp, #48]; stp x22, x21, [sp, #64]
    #   stp x20, x19, [sp, #80]; stp x29, x30, [sp, #96]; add x29, sp, #96; mov x19, x2; mov x21, x1
    #   mov x20, x0; adrp x23, #31956992; ldrb w8, [x23, #2600]
    Signature('lockItem',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 d000f3d7 '
              '3968a2e8'),
    # pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
    #   stp x29, x30, [sp, #80]; add x29, sp, #80; mov x20, x1; mov x19, x0; adrp x22, #31956992
    #   ldrb w8, [x22, #2600]; adrp x21, #-27684864; add x21, x21, #3492; cmp w8, #10; b.hi #84
    #   ldrb w8, [x19, #140]; tbz w8, #0, #52; ldr x16, [x19]; mov x17, x19; movk x17, #52641, lsl #48
    #   autda x16, x17; mov x17, #488; add x16, x16, x17; ldr x8, [x16]; mov x0, x19; mov x1, #0
    #   movk x16, #3228, lsl #48; blraa x8, x16; b #12; adrp x0, #-27684864; add x0, x0, #1331
    #   stp x0, x21, [sp]; adrp x0, #-27750400
    Signature('unlockItem',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f3d6 3968a2c8 b0ff2cd5 '
              '913692b5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 b0ff2cc0 9114cc00 a90057e0 b0ff2c40', True),
    # pacibsp; sub sp, sp, #128; stp x26, x25, [sp, #48]; stp x24, x23, [sp, #64]
    #   stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]; stp x29, x30, [sp, #112]; add x29, sp, #112
    #   mov x20, x1; mov x19, x0; ldr x24, [x2]; lsr x25, x24, #32; adrp x23, #31956992
    #   ldrb w8, [x23, #2600]; lsr w21, w24, #16; adrp x22, #-27684864
    Signature('handleSEPMessage',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 '
              'd360ff19 d000f3d7 3968a2e8 53107f15 b0ff2cd6'),
    # pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
    #   stp x29, x30, [sp, #80]; add x29, sp, #80; mov x20, x2; mov x19, x1; mov x21, x0
    #   ldr x0, [x0, #328]; cbnz x0, #20; mov x0, x21; bl #2220; ldr x0, [x21, #328]; cbz x0, #236
    #   ldr x16, [x0]
    Signature('readFromSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a400 b50000a0 '
              'aa1503e0 9400022b f940a6a0 b4000760 f9400010'),
    # pacibsp; sub sp, sp, #144; stp x28, x27, [sp, #48]; stp x26, x25, [sp, #64]
    #   stp x24, x23, [sp, #80]; stp x22, x21, [sp, #96]; stp x20, x19, [sp, #112]
    #   stp x29, x30, [sp, #128]; add x29, sp, #128; mov x20, x5; mov x21, x4; mov x22, x3; mov x23, x2
    #   mov x24, x1; mov x19, x0; adrp x28, #31952896
    Signature('writeToSEPBuffer',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 '
              'aa0303f6 aa0203f7 aa0103f8 aa0003f3 b000f3dc'),
    # pacibsp; sub sp, sp, #144; stp x26, x25, [sp, #64]; stp x24, x23, [sp, #80]
    #   stp x22, x21, [sp, #96]; stp x20, x19, [sp, #112]; stp x29, x30, [sp, #128]; add x29, sp, #128
    #   mov x23, x4; mov x21, x3; mov x22, x2; mov x20, x1; mov x19, x0; adrp x25, #31952896
    #   ldrb w8, [x25, #2600]; cmp w8, #10
    Signature('sendSEPMessage',
              'd503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 '
              'aa0103f4 aa0003f3 b000f3d9 3968a328 7100291f'),
    # pacibsp; sub sp, sp, #96; stp x22, x21, [sp, #48]; stp x20, x19, [sp, #64]
    #   stp x29, x30, [sp, #80]; add x29, sp, #80; cbz x1, #280; mov x19, x2; mov x20, x1
    #   ldr x16, [x1]; mov x17, x1; movk x17, #52641, lsl #48; autda x16, x17; ldr x8, [x16, #120]!
    #   mov x0, x1; movk x16, #5079, lsl #48
    Signature('clearSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 '
              'f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0'),
    # pacibsp; sub sp, sp, #144; stp x28, x27, [sp, #48]; stp x26, x25, [sp, #64]
    #   stp x24, x23, [sp, #80]; stp x22, x21, [sp, #96]; stp x20, x19, [sp, #112]
    #   stp x29, x30, [sp, #128]; add x29, sp, #128; mov x19, x0; adrp x27, #31952896
    #   ldrb w8, [x27, #2600]; cmp w8, #10; b.hi #92; ldrb w8, [x19, #140]; tbz w8, #0, #52
    Signature('getSEPEndpoint',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 b000f3db '
              '3968a368 7100291f 540002e8 39423268 360001a8'),
    # pacibsp; sub sp, sp, #128; stp x26, x25, [sp, #48]; stp x24, x23, [sp, #64]
    #   stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]; stp x29, x30, [sp, #112]; add x29, sp, #112
    #   mov x19, x0; adrp x25, #31948800; ldrb w8, [x25, #2600]; cmp w8, #40; b.hi #92
    #   ldrb w8, [x19, #140]; tbz w8, #0, #52; ldr x16, [x19]
    Signature('powerOffActionGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f3d9 3968a328 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # pacibsp; sub sp, sp, #128; stp x26, x25, [sp, #48]; stp x24, x23, [sp, #64]
    #   stp x22, x21, [sp, #80]; stp x20, x19, [sp, #96]; stp x29, x30, [sp, #112]; add x29, sp, #112
    #   mov x19, x0; adrp x8, #31948800; ldrb w8, [x8, #2600]; cmp w8, #40; b.hi #92
    #   ldrb w8, [x19, #140]; tbz w8, #0, #52; ldr x16, [x19]
    Signature('sepManagerMatchedGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f3c8 3968a108 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # pacibsp; sub sp, sp, #112; stp x24, x23, [sp, #48]; stp x22, x21, [sp, #64]
    #   stp x20, x19, [sp, #80]; stp x29, x30, [sp, #96]; add x29, sp, #96; mov x20, x1; mov x19, x0
    #   adrp x24, #31899648; ldrb w8, [x24, #2600]; adrp x23, #-27742208; add x23, x23, #3303
    #   cmp w8, #40; b.hi #56; ldrb w8, [x19, #140]; tbz w8, #0, #116; bl #-48444
    #   movk x17, #52641, lsl #48; autda x16, x17; mov x17, #488; add x16, x16, x17; ldr x8, [x16]
    #   mov x0, x19; mov x1, #0; movk x16, #3228, lsl #48; blraa x8, x16; b #76; cbnz x20, #100
    #   mov w8, #1709; adrp x9, #-27742208; add x9, x9, #1651
    Signature('setPowerStateGated',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 9000f378 3968a308 '
              'f0ff2c57 91339ef7 7100a11f 540001c8 39423268 360003a8 97ffd0b1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000013 b5000334 5280d5a8 f0ff2c49 9119cd29', True),
)

# ------------------------------------------------------------------------------------------------------------------
# iOS 27.0 release line (24A435 / 24A437 / 24A446). This release enabled BTI for the kernelcache, so every
# method gained a BTI C landing pad. The words start at the PACIBSP after it, except
# performLoggingLevelQueryGated, whose entry is the pad itself. The stub write is placed after any pad
# (core.ARM64.stub_start) because several of these methods are only reached through a taken address.
# All 26 methods keep the beta-4 relative order.
VARIANTS['ios27-24A435-acm-v1'] = (
    # recorded at file offset 0x20bfd50; 11/12 words identical to the beta-4 recording.
    Signature('sepManagerMatchedThreadCallHandler',
              'd503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 '
              'd0000030'),
    # recorded at file offset 0x20c0434; 15/16 words identical to the beta-4 recording.
    Signature('callPlatformFunction',
              'd503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf '
              'f81ed3bf d10083a4 94000037 a9457bfd 910183ff'),
    # recorded at file offset 0x20c04bc; 16/16 words identical to the beta-4 recording.
    Signature('cmdContextV2',
              'd503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 '
              'f81f53bf f81ed3bf d10083a4 94000014 a9457bfd'),
    # recorded at file offset 0x20c0548; 15/16 words identical to the beta-4 recording.
    Signature('cmdContextV3',
              'd503237f d10243ff a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd b4000564 aa0403f7 aa0303f3 aa0203f4 '
              'aa0103f5 aa0003f6 97ffb3eb aa0003f8 394032e1'),
    # recorded at file offset 0x20c0824; 12/16 words identical to the beta-4 recording.
    Signature('performCommandGated',
              'd503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 '
              'aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0'),
    # recorded at file offset 0x20c1314; 15/16 words identical to the beta-4 recording.
    Signature('_performKernelControl',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 '
              'aa0303f7 aa0203f8 aa0103f4 aa0003f3 d000f29a'),
    # recorded at file offset 0x20c16d4; 16/16 words identical to the beta-4 recording.
    Signature('_performCommand',
              'd503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 '
              'aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6'),
    # recorded at file offset 0x20c1900; 14/16 words identical to the beta-4 recording.
    Signature('processSCRDResponsePayload',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f295 3964e2a8 7100291f '
              '540002e8 39423268 360001a8 f9400270 aa1303f1'),
    # recorded at file offset 0x20c1b30; 15/16 words identical to the beta-4 recording.
    Signature('scheduleDblClickDeferredAck',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 '
              'f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910'),
    # recorded at file offset 0x20c1c54; 25/32 words identical to the beta-4 recording.
    Signature('updateAnalytics',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f296 3964e2c8 b0ff2f95 '
              '9106ceb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 f0ff2f60 913b9800 a90057e0 f0ff2ee0', True),
    # recorded at file offset 0x20c1dbc; 14/16 words identical to the beta-4 recording.
    Signature('performSCRDInitialization',
              'd503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f294 3964e288 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431'),
    # recorded at file offset 0x20c2084; 27/32 words identical to the beta-4 recording.
    Signature('sendSEPCommand',
              'd503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 '
              'aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 b000f29b 3964e368 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0', True),
    # recorded at file offset 0x20c2b00; 13/16 words identical to the beta-4 recording.
    Signature('_setPropertiesGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 90ff7028 '
              'f9443908 f9400101 aa1303e0 94003dca b4001640'),
    # recorded at file offset 0x20c2f8c; 15/16 words identical to the beta-4 recording.
    Signature('performDoubleClickQueryGated',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 '
              'd2800004 d2800005 d2800006 52800027 97fffc2e'),
    # recorded at file offset 0x20c307c; 8/10 words identical to the beta-4 recording.
    Signature('performLoggingLevelQueryGated',
              'd503245f b40000c1 52800000 9000f288 3964e108 f9000028 d65f03c0 d503237f d10103ff a9037bfd'),
    # recorded at file offset 0x20c34b8; 10/12 words identical to the beta-4 recording.
    Signature('lockItem',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 9000f297 '
              '3964e2e8'),
    # recorded at file offset 0x20c36e8; 25/32 words identical to the beta-4 recording.
    Signature('unlockItem',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f296 3964e2c8 d0ff2f75 '
              '912172b5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 b0ff2f60 913b9800 a90057e0 b0ff2ee0', True),
    # recorded at file offset 0x20c3bac; 13/16 words identical to the beta-4 recording.
    Signature('handleSEPMessage',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 '
              'd360ff19 9000f297 3964e2e8 53107f15 d0ff2f76'),
    # recorded at file offset 0x20c3e98; 13/16 words identical to the beta-4 recording.
    Signature('readFromSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 '
              'aa1503e0 9400022e f940aaa0 b4000760 f9400010'),
    # recorded at file offset 0x20c3ffc; 15/16 words identical to the beta-4 recording.
    Signature('writeToSEPBuffer',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 '
              'aa0303f6 aa0203f7 aa0103f8 aa0003f3 f000f27c'),
    # recorded at file offset 0x20c43a8; 14/16 words identical to the beta-4 recording.
    Signature('sendSEPMessage',
              'd503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 '
              'aa0103f4 aa0003f3 f000f279 3964e328 7100291f'),
    # recorded at file offset 0x20c45e4; 16/16 words identical to the beta-4 recording.
    Signature('clearSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 '
              'f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0'),
    # recorded at file offset 0x20c4784; 14/16 words identical to the beta-4 recording.
    Signature('getSEPEndpoint',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 f000f27b '
              '3964e368 7100291f 540002e8 39423268 360001a8'),
    # recorded at file offset 0x20c53d0; 14/16 words identical to the beta-4 recording.
    Signature('powerOffActionGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f279 3964e328 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x20c5688; 14/16 words identical to the beta-4 recording.
    Signature('sepManagerMatchedGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f268 3964e108 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x20d1b2c; 19/32 words identical to the beta-4 recording.
    Signature('setPowerStateGated',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 d000f217 3964e2e8 '
              '90ff2f16 911aded6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 f0ff2e60 91325400', True),
)

# ------------------------------------------------------------------------------------------------------------------
# iOS 27.2 beta 1 (24B5084k). Close to the 24A435 family: only cmdContextV3 changed (an extra callee-saved
# pair and a 0xa0 frame). Re-recorded from this build rather than shared, so one build line never matches
# under another line's name. updateAnalytics and unlockItem are located positionally (the candidate
# entries after lockItem sit at 0x230, 0x3a0, 0x4c8, 0x5f0 on both builds).
VARIANTS['ios272-24B5084k-acm-v1'] = (
    # recorded at file offset 0x217a600
    Signature('sepManagerMatchedThreadCallHandler',
              'd503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 '
              'b0000030'),
    # recorded at file offset 0x217ace4
    Signature('callPlatformFunction',
              'd503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf '
              'f81ed3bf d10083a4 94000037 a9457bfd 910183ff'),
    # recorded at file offset 0x217ad6c
    Signature('cmdContextV2',
              'd503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 '
              'f81f53bf f81ed3bf d10083a4 94000014 a9457bfd'),
    # recorded at file offset 0x217adf8
    Signature('cmdContextV3',
              'd503237f d10283ff a90567fa a9065ff8 a90757f6 a9084ff4 a9097bfd 910243fd b40005e4 aa0403f8 aa0303f3 '
              'aa0203f4 aa0103f5 aa0003f7 97ffb3a0 aa0003f9'),
    # recorded at file offset 0x217b190
    Signature('performCommandGated',
              'd503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 '
              'aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0'),
    # recorded at file offset 0x217bc80
    Signature('_performKernelControl',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 '
              'aa0303f7 aa0203f8 aa0103f4 aa0003f3 d000f71a'),
    # recorded at file offset 0x217c040
    Signature('_performCommand',
              'd503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 '
              'aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6'),
    # recorded at file offset 0x217c26c
    Signature('processSCRDResponsePayload',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 b000f715 394902a8 7100291f '
              '540002e8 39423268 360001a8 f9400270 aa1303f1'),
    # recorded at file offset 0x217c49c
    Signature('scheduleDblClickDeferredAck',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 '
              'f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910'),
    # recorded at file offset 0x217c5c0
    Signature('updateAnalytics',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 b000f716 394902c8 f0ff2a55 '
              '913e5ab5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 d0ff2a40 91321800 a90057e0 d0ff29c0', True),
    # recorded at file offset 0x217c728
    Signature('performSCRDInitialization',
              'd503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 b000f714 39490288 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431'),
    # recorded at file offset 0x217c9f0
    Signature('sendSEPCommand',
              'd503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 '
              'aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 b000f71b 39490368 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0', True),
    # recorded at file offset 0x217d46c
    Signature('_setPropertiesGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 b0ff6ca8 '
              'f947a108 f9400101 aa1303e0 94003dca b4001640'),
    # recorded at file offset 0x217d8f8
    Signature('performDoubleClickQueryGated',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 '
              'd2800004 d2800005 d2800006 52800027 97fffc2e'),
    # recorded at file offset 0x217d9e8
    Signature('performLoggingLevelQueryGated',
              'd503245f b40000c1 52800000 9000f708 39490108 f9000028 d65f03c0 d503237f d10103ff a9037bfd'),
    # recorded at file offset 0x217de24
    Signature('lockItem',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 9000f717 '
              '394902e8'),
    # recorded at file offset 0x217e054
    Signature('unlockItem',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 f000f6f6 394902c8 b0ff2a55 '
              '9118feb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 90ff2a40 91321800 a90057e0 90ff29c0', True),
    # recorded at file offset 0x217e518
    Signature('handleSEPMessage',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 '
              'd360ff19 f000f6f7 394902e8 53107f15 b0ff2a56'),
    # recorded at file offset 0x217e804
    Signature('readFromSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 '
              'aa1503e0 9400022e f940aaa0 b4000760 f9400010'),
    # recorded at file offset 0x217e968
    Signature('writeToSEPBuffer',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 '
              'aa0303f6 aa0203f7 aa0103f8 aa0003f3 f000f6fc'),
    # recorded at file offset 0x217ed14
    Signature('sendSEPMessage',
              'd503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 '
              'aa0103f4 aa0003f3 f000f6f9 39490328 7100291f'),
    # recorded at file offset 0x217ef50
    Signature('clearSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 '
              'f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0'),
    # recorded at file offset 0x217f0f0
    Signature('getSEPEndpoint',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 d000f6fb '
              '39490368 7100291f 540002e8 39423268 360001a8'),
    # recorded at file offset 0x217fd3c
    Signature('powerOffActionGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f6f9 39490328 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x217fff4
    Signature('sepManagerMatchedGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 b000f6e8 39490108 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x218c498
    Signature('setPowerStateGated',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 b000f697 394902e8 '
              'f0ff29d6 91126ad6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 d0ff2940 91271400', True),
)

# ------------------------------------------------------------------------------------------------------------------
# iOS 27.2 beta 2 (24B5089g). Shape-identical to beta 1; recorded separately because the raw words differ
# in the relinked fields that allow_data_layout_drift masks.
VARIANTS['ios272b2-24B5089g-acm-v1'] = (
    # recorded at file offset 0x217bfc0
    Signature('sepManagerMatchedThreadCallHandler',
              'd503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 '
              'd0000030'),
    # recorded at file offset 0x217c6a4
    Signature('callPlatformFunction',
              'd503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf '
              'f81ed3bf d10083a4 94000037 a9457bfd 910183ff'),
    # recorded at file offset 0x217c72c
    Signature('cmdContextV2',
              'd503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 '
              'f81f53bf f81ed3bf d10083a4 94000014 a9457bfd'),
    # recorded at file offset 0x217c7b8
    Signature('cmdContextV3',
              'd503237f d10283ff a90567fa a9065ff8 a90757f6 a9084ff4 a9097bfd 910243fd b40005e4 aa0403f8 aa0303f3 '
              'aa0203f4 aa0103f5 aa0003f7 97ffb3a0 aa0003f9'),
    # recorded at file offset 0x217cb50
    Signature('performCommandGated',
              'd503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 '
              'aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0'),
    # recorded at file offset 0x217d640
    Signature('_performKernelControl',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 '
              'aa0303f7 aa0203f8 aa0103f4 aa0003f3 9000f73a'),
    # recorded at file offset 0x217da00
    Signature('_performCommand',
              'd503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 '
              'aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6'),
    # recorded at file offset 0x217dc2c
    Signature('processSCRDResponsePayload',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f735 3948c2a8 7100291f '
              '540002e8 39423268 360001a8 f9400270 aa1303f1'),
    # recorded at file offset 0x217de5c
    Signature('scheduleDblClickDeferredAck',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 '
              'f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910'),
    # recorded at file offset 0x217df80
    Signature('updateAnalytics',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f736 3948c2c8 f0ff2a55 '
              '91301ab5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 d0ff2a40 9123d800 a90057e0 d0ff29c0', True),
    # recorded at file offset 0x217e0e8
    Signature('performSCRDInitialization',
              'd503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 f000f714 3948c288 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431'),
    # recorded at file offset 0x217e3b0
    Signature('sendSEPCommand',
              'd503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 '
              'aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 f000f71b 3948c368 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0', True),
    # recorded at file offset 0x217ee2c
    Signature('_setPropertiesGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 90ff6ca8 '
              'f947d508 f9400101 aa1303e0 94003dca b4001640'),
    # recorded at file offset 0x217f2b8
    Signature('performDoubleClickQueryGated',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 '
              'd2800004 d2800005 d2800006 52800027 97fffc2e'),
    # recorded at file offset 0x217f3a8
    Signature('performLoggingLevelQueryGated',
              'd503245f b40000c1 52800000 d000f708 3948c108 f9000028 d65f03c0 d503237f d10103ff a9037bfd'),
    # recorded at file offset 0x217f7e4
    Signature('lockItem',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 d000f717 '
              '3948c2e8'),
    # recorded at file offset 0x217fa14
    Signature('unlockItem',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f716 3948c2c8 b0ff2a55 '
              '910abeb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 90ff2a40 9123d800 a90057e0 90ff29c0', True),
    # recorded at file offset 0x217fed8
    Signature('handleSEPMessage',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 '
              'd360ff19 d000f717 3948c2e8 53107f15 b0ff2a56'),
    # recorded at file offset 0x21801c4
    Signature('readFromSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 '
              'aa1503e0 9400022e f940aaa0 b4000760 f9400010'),
    # recorded at file offset 0x2180328
    Signature('writeToSEPBuffer',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 '
              'aa0303f6 aa0203f7 aa0103f8 aa0003f3 b000f71c'),
    # recorded at file offset 0x21806d4
    Signature('sendSEPMessage',
              'd503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 '
              'aa0103f4 aa0003f3 b000f719 3948c328 7100291f'),
    # recorded at file offset 0x2180910
    Signature('clearSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 '
              'f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0'),
    # recorded at file offset 0x2180ab0
    Signature('getSEPEndpoint',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 b000f71b '
              '3948c368 7100291f 540002e8 39423268 360001a8'),
    # recorded at file offset 0x21816fc
    Signature('powerOffActionGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f719 3948c328 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x21819b4
    Signature('sepManagerMatchedGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f708 3948c108 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x218de58
    Signature('setPowerStateGated',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 9000f6b7 3948c2e8 '
              'f0ff29d6 91042ad6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 d0ff2940 9118d400', True),
)

# ------------------------------------------------------------------------------------------------------------------
# iOS 27.2 beta 3 (24B5099f). Shape-identical to beta 2; recorded separately for the same reason.
VARIANTS['ios272b3-24B5099f-acm-v1'] = (
    # recorded at file offset 0x21015b0
    Signature('sepManagerMatchedThreadCallHandler',
              'd503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 '
              'b0000030'),
    # recorded at file offset 0x2101c94
    Signature('callPlatformFunction',
              'd503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf '
              'f81ed3bf d10083a4 94000037 a9457bfd 910183ff'),
    # recorded at file offset 0x2101d1c
    Signature('cmdContextV2',
              'd503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 '
              'f81f53bf f81ed3bf d10083a4 94000014 a9457bfd'),
    # recorded at file offset 0x2101da8
    Signature('cmdContextV3',
              'd503237f d10283ff a90567fa a9065ff8 a90757f6 a9084ff4 a9097bfd 910243fd b40005e4 aa0403f8 aa0303f3 '
              'aa0203f4 aa0103f5 aa0003f7 97ffb3a0 aa0003f9'),
    # recorded at file offset 0x2102140
    Signature('performCommandGated',
              'd503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 '
              'aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0'),
    # recorded at file offset 0x2102c30
    Signature('_performKernelControl',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 '
              'aa0303f7 aa0203f8 aa0103f4 aa0003f3 b000f39a'),
    # recorded at file offset 0x2102ff0
    Signature('_performCommand',
              'd503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 '
              'aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6'),
    # recorded at file offset 0x210321c
    Signature('processSCRDResponsePayload',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f395 3971c2a8 7100291f '
              '540002e8 39423268 360001a8 f9400270 aa1303f1'),
    # recorded at file offset 0x210344c
    Signature('scheduleDblClickDeferredAck',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 '
              'f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910'),
    # recorded at file offset 0x2103570
    Signature('updateAnalytics',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f396 3971c2c8 d0ff2dd5 '
              '912b1ab5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 b0ff2dc0 911ed800 a90057e0 b0ff2d40', True),
    # recorded at file offset 0x21036d8
    Signature('performSCRDInitialization',
              'd503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f394 3971c288 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431'),
    # recorded at file offset 0x21039a0
    Signature('sendSEPCommand',
              'd503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 '
              'aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 9000f39b 3971c368 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0', True),
    # recorded at file offset 0x210441c
    Signature('_setPropertiesGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 f0ff6ea8 '
              'f946ad08 f9400101 aa1303e0 94003dca b4001640'),
    # recorded at file offset 0x21048a8
    Signature('performDoubleClickQueryGated',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 '
              'd2800004 d2800005 d2800006 52800027 97fffc2e'),
    # recorded at file offset 0x2104998
    Signature('performLoggingLevelQueryGated',
              'd503245f b40000c1 52800000 f000f368 3971c108 f9000028 d65f03c0 d503237f d10103ff a9037bfd'),
    # recorded at file offset 0x2104dd4
    Signature('lockItem',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 f000f377 '
              '3971c2e8'),
    # recorded at file offset 0x2105004
    Signature('unlockItem',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f376 3971c2c8 90ff2dd5 '
              '9105beb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 f0ff2da0 911ed800 a90057e0 f0ff2d20', True),
    # recorded at file offset 0x21054c8
    Signature('handleSEPMessage',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 '
              'd360ff19 d000f377 3971c2e8 53107f15 90ff2dd6'),
    # recorded at file offset 0x21057b4
    Signature('readFromSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 '
              'aa1503e0 9400022e f940aaa0 b4000760 f9400010'),
    # recorded at file offset 0x2105918
    Signature('writeToSEPBuffer',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 '
              'aa0303f6 aa0203f7 aa0103f8 aa0003f3 d000f37c'),
    # recorded at file offset 0x2105cc4
    Signature('sendSEPMessage',
              'd503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 '
              'aa0103f4 aa0003f3 d000f379 3971c328 7100291f'),
    # recorded at file offset 0x2105f00
    Signature('clearSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 '
              'f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0'),
    # recorded at file offset 0x21060a0
    Signature('getSEPEndpoint',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 b000f37b '
              '3971c368 7100291f 540002e8 39423268 360001a8'),
    # recorded at file offset 0x2106cec
    Signature('powerOffActionGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 b000f379 3971c328 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x2106fa4
    Signature('sepManagerMatchedGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 b000f368 3971c108 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x2113448
    Signature('setPowerStateGated',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 9000f317 3971c2e8 '
              'b0ff2d56 913f2ad6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 b0ff2cc0 9113d400', True),
)

# ------------------------------------------------------------------------------------------------------------------
# iOS 27.2 beta 4 (24B5110a). Only updateAnalytics and unlockItem are scored: sendSEPCommand and
# setPowerStateGated match uniquely here, so they take the strict exact match and a drifted body fails
# closed. Candidate entries between the scored functions' neighbours: one at 0x124 after
# scheduleDblClickDeferredAck; four at 0x230, 0x3a0, 0x4c8, 0x5f0 after lockItem (the first is unlockItem).
VARIANTS['ios272b4-24B5110a-acm-v1'] = (
    # recorded at file offset 0x2101b80
    Signature('sepManagerMatchedThreadCallHandler',
              'd503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 '
              'd0000030'),
    # recorded at file offset 0x2102264
    Signature('callPlatformFunction',
              'd503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf '
              'f81ed3bf d10083a4 94000037 a9457bfd 910183ff'),
    # recorded at file offset 0x21022ec
    Signature('cmdContextV2',
              'd503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 '
              'f81f53bf f81ed3bf d10083a4 94000014 a9457bfd'),
    # recorded at file offset 0x2102378
    Signature('cmdContextV3',
              'd503237f d10283ff a90567fa a9065ff8 a90757f6 a9084ff4 a9097bfd 910243fd b40005e4 aa0403f8 aa0303f3 '
              'aa0203f4 aa0103f5 aa0003f7 97ffb3a0 aa0003f9'),
    # recorded at file offset 0x2102710
    Signature('performCommandGated',
              'd503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 '
              'aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0'),
    # recorded at file offset 0x2103200
    Signature('_performKernelControl',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 '
              'aa0303f7 aa0203f8 aa0103f4 aa0003f3 9000f3ba'),
    # recorded at file offset 0x21035c0
    Signature('_performCommand',
              'd503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 '
              'aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6'),
    # recorded at file offset 0x21037ec
    Signature('processSCRDResponsePayload',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f3b5 3971c2a8 7100291f '
              '540002e8 39423268 360001a8 f9400270 aa1303f1'),
    # recorded at file offset 0x2103a1c
    Signature('scheduleDblClickDeferredAck',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 '
              'f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910'),
    # recorded at file offset 0x2103b40
    Signature('updateAnalytics',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f3b6 3971c2c8 d0ff2dd5 '
              '91399ab5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 b0ff2dc0 912d5800 a90057e0 b0ff2d40', True),
    # recorded at file offset 0x2103ca8
    Signature('performSCRDInitialization',
              'd503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f3b4 3971c288 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431'),
    # recorded at file offset 0x2103f70
    Signature('sendSEPCommand',
              'd503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 '
              'aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 9000f3bb 3971c368 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0'),
    # recorded at file offset 0x21049ec
    Signature('_setPropertiesGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 f0ff6ea8 '
              'f946c508 f9400101 aa1303e0 94003dca b4001640'),
    # recorded at file offset 0x2104e78
    Signature('performDoubleClickQueryGated',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 '
              'd2800004 d2800005 d2800006 52800027 97fffc2e'),
    # recorded at file offset 0x2104f68
    Signature('performLoggingLevelQueryGated',
              'd503245f b40000c1 52800000 f000f388 3971c108 f9000028 d65f03c0 d503237f d10103ff a9037bfd'),
    # recorded at file offset 0x21053a4
    Signature('lockItem',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 d000f397 '
              '3971c2e8'),
    # recorded at file offset 0x21055d4
    Signature('unlockItem',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f396 3971c2c8 90ff2dd5 '
              '91143eb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 f0ff2da0 912d5800 a90057e0 f0ff2d20', True),
    # recorded at file offset 0x2105a98
    Signature('handleSEPMessage',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 '
              'd360ff19 d000f397 3971c2e8 53107f15 90ff2dd6'),
    # recorded at file offset 0x2105d84
    Signature('readFromSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 '
              'aa1503e0 9400022e f940aaa0 b4000760 f9400010'),
    # recorded at file offset 0x2105ee8
    Signature('writeToSEPBuffer',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 '
              'aa0303f6 aa0203f7 aa0103f8 aa0003f3 d000f39c'),
    # recorded at file offset 0x2106294
    Signature('sendSEPMessage',
              'd503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 '
              'aa0103f4 aa0003f3 b000f399 3971c328 7100291f'),
    # recorded at file offset 0x21064d0
    Signature('clearSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 '
              'f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0'),
    # recorded at file offset 0x2106670
    Signature('getSEPEndpoint',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 b000f39b '
              '3971c368 7100291f 540002e8 39423268 360001a8'),
    # recorded at file offset 0x21072bc
    Signature('powerOffActionGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f399 3971c328 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x2107574
    Signature('sepManagerMatchedGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 9000f388 3971c108 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x2113a18
    Signature('setPowerStateGated',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 9000f337 3971c2e8 '
              'd0ff2d56 910daad6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 b0ff2cc0 91225400'),
)

# ------------------------------------------------------------------------------------------------------------------
# iOS 27.2 release (24B119). Shape-identical to beta 4 (same two scored entries, same neighbour deltas);
# recorded separately because the raw words differ in the relinked fields.
VARIANTS['ios272-24B119-acm-v1'] = (
    # recorded at file offset 0x20f8010
    Signature('sepManagerMatchedThreadCallHandler',
              'd503237f d10103ff a9037bfd 9100c3fd f9404c00 f9400010 aa0003f1 f2f9b431 dac11a30 f84e8e09 aa1003e8 '
              'b0000030'),
    # recorded at file offset 0x20f86f4
    Signature('callPlatformFunction',
              'd503237f d10183ff a9057bfd 910143fd b40001a4 b9400088 b81e03a8 f9400488 f81e43a8 381ec3bf f81f53bf '
              'f81ed3bf d10083a4 94000037 a9457bfd 910183ff'),
    # recorded at file offset 0x20f877c
    Signature('cmdContextV2',
              'd503237f d10183ff a9057bfd 910143fd b40001c4 b9400088 b81e03a8 f8404088 f81e43a8 39403088 381ec3a8 '
              'f81f53bf f81ed3bf d10083a4 94000014 a9457bfd'),
    # recorded at file offset 0x20f8808
    Signature('cmdContextV3',
              'd503237f d10283ff a90567fa a9065ff8 a90757f6 a9084ff4 a9097bfd 910243fd b40005e4 aa0403f8 aa0303f3 '
              'aa0203f4 aa0103f5 aa0003f7 97ffb3a0 aa0003f9'),
    # recorded at file offset 0x20f8ba0
    Signature('performCommandGated',
              'd503237f d10543ff a90f6ffc a91067fa a9115ff8 a91257f6 a9134ff4 a9147bfd 910503fd aa0403f4 aa0303f5 '
              'aa0203f6 aa0103f9 aa0003f8 6f00e400 ad3c03a0'),
    # recorded at file offset 0x20f9690
    Signature('_performKernelControl',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f5 aa0403f6 '
              'aa0303f7 aa0203f8 aa0103f4 aa0003f3 d000f2da'),
    # recorded at file offset 0x20f9a50
    Signature('_performCommand',
              'd503237f d102c3ff a9056ffc a90667fa a9075ff8 a90857f6 a9094ff4 a90a7bfd 910283fd aa0603f8 aa0503f9 '
              'aa0403f4 aa0303f7 aa0203f3 aa0103f5 aa0003f6'),
    # recorded at file offset 0x20f9c7c
    Signature('processSCRDResponsePayload',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f2d5 396e42a8 7100291f '
              '540002e8 39423268 360001a8 f9400270 aa1303f1'),
    # recorded at file offset 0x20f9eac
    Signature('scheduleDblClickDeferredAck',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd aa0003f3 52800001 94000fa6 f9408e60 f9400010 aa0003f1 '
              'f2f9b431 dac11a30 f84b0e08 f2f362d0 d73f0910'),
    # recorded at file offset 0x20f9fd0
    Signature('updateAnalytics',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 d000f2d6 396e42c8 90ff2e15 '
              '91251ab5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 d0ff2de0 9118d800 a90057e0 d0ff2d60', True),
    # recorded at file offset 0x20fa138
    Signature('performSCRDInitialization',
              'd503237f d10203ff a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 b000f2d4 396e4288 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431'),
    # recorded at file offset 0x20fa400
    Signature('sendSEPCommand',
              'd503237f d10443ff a90b6ffc a90c67fa a90d5ff8 a90e57f6 a90f4ff4 a9107bfd 910403fd aa0703fc aa0603f7 '
              'aa0503f9 aa0403f5 aa0303f8 aa0203f6 aa0103f4 aa0003f3 f81a03a4 b000f2db 396e4368 7100291f 540002e8 '
              '39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 f9400208 aa1303e0'),
    # recorded at file offset 0x20fae7c
    Signature('_setPropertiesGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f3 aa0003f4 b0ff6ec8 '
              'f9466508 f9400101 aa1303e0 94003dca b4001640'),
    # recorded at file offset 0x20fb308
    Signature('performDoubleClickQueryGated',
              'd503237f d10143ff a9034ff4 a9047bfd 910103fd b4000261 aa0103f3 a9007fff 52800041 52800002 d2800003 '
              'd2800004 d2800005 d2800006 52800027 97fffc2e'),
    # recorded at file offset 0x20fb3f8
    Signature('performLoggingLevelQueryGated',
              'd503245f b40000c1 52800000 9000f2c8 396e4108 f9000028 d65f03c0 d503237f d10103ff a9037bfd'),
    # recorded at file offset 0x20fb834
    Signature('lockItem',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0203f3 aa0103f5 aa0003f4 9000f2d7 '
              '396e42e8'),
    # recorded at file offset 0x20fba64
    Signature('unlockItem',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0103f4 aa0003f3 9000f2d6 396e42c8 b0ff2df5 '
              '913fbeb5 7100291f 540002a8 39423268 360001a8 f9400270 aa1303f1 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000003 b0ff2de0 9118d800 a90057e0 b0ff2d60', True),
    # recorded at file offset 0x20fbf28
    Signature('handleSEPMessage',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0103f4 aa0003f3 f9400058 '
              'd360ff19 9000f2d7 396e42e8 53107f15 d0ff2df6'),
    # recorded at file offset 0x20fc214
    Signature('readFromSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd aa0203f4 aa0103f3 aa0003f5 f940a800 b50000a0 '
              'aa1503e0 9400022e f940aaa0 b4000760 f9400010'),
    # recorded at file offset 0x20fc378
    Signature('writeToSEPBuffer',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0503f4 aa0403f5 '
              'aa0303f6 aa0203f7 aa0103f8 aa0003f3 f000f2bc'),
    # recorded at file offset 0x20fc724
    Signature('sendSEPMessage',
              'd503237f d10243ff a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0403f7 aa0303f5 aa0203f6 '
              'aa0103f4 aa0003f3 f000f2b9 396e4328 7100291f'),
    # recorded at file offset 0x20fc960
    Signature('clearSEPBuffer',
              'd503237f d10183ff a90357f6 a9044ff4 a9057bfd 910143fd b40008c1 aa0203f3 aa0103f4 f9400030 aa0103f1 '
              'f2f9b431 dac11a30 f8478e08 aa0103e0 f2e27af0'),
    # recorded at file offset 0x20fcb00
    Signature('getSEPEndpoint',
              'd503237f d10243ff a9036ffc a90467fa a9055ff8 a90657f6 a9074ff4 a9087bfd 910203fd aa0003f3 f000f2bb '
              '396e4368 7100291f 540002e8 39423268 360001a8'),
    # recorded at file offset 0x20fd74c
    Signature('powerOffActionGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f2b9 396e4328 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x20fda04
    Signature('sepManagerMatchedGated',
              'd503237f d10203ff a90367fa a9045ff8 a90557f6 a9064ff4 a9077bfd 9101c3fd aa0003f3 d000f2a8 396e4108 '
              '7100a11f 540002e8 39423268 360001a8 f9400270'),
    # recorded at file offset 0x2109ea8
    Signature('setPowerStateGated',
              'd503237f d101c3ff a9035ff8 a90457f6 a9054ff4 a9067bfd 910183fd aa0103f4 aa0003f3 d000f257 396e42e8 '
              'f0ff2d76 91392ad6 7100291f 54000268 39423268 36000188 97ffd058 f2f9b431 dac11a30 d2803d11 8b110210 '
              'f9400208 aa1303e0 d2800001 f2e19390 d73f0910 14000002 97ffd047 a9005be0 f0ff2ce0 910dd400'),
)

