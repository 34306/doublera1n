#!/usr/bin/env python3
"""
iBoot (mBoot unified image) patcher for T8030 / iOS 27.x, booted from pwned DFU.
--kpf takes JSON patch records (component, id, offset, originalBytes, replacementBytes).

Patches (all discovered by pattern, no hard-coded offsets):
  1. image4 validation callback -> success          (anchor "Unknown ASN1 type %llu\\n")
  2. boot-args snprintf("%s") -> our literal          (ADRP X2/ADD X2/ADD X0,SP/MOV W1,#0x400/BL)
  3. console command "memboot" -> fsboot handler      (so `irecovery -c memboot` boots from NAND
                                                       with the device's real APTicket / SEP)
Optional: --local/--clear-remote (behave like a NAND boot), --no-autoboot, --rd-rename (rd=md0 -> jb=md0),
          --kpf (in-RAM patching of kernel/TXM/SPTM before the jump to the kernel, see kpf.py)
Usage: patch_iboot.py in.raw out.raw [--boot-args "..."] [--no-fsboot]
"""
import argparse, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kpf as _layout   # set_layout / handler_size / TEXT_END

BASE = 0x19C050000   # replaced from the image header in main() (kpf.set_layout)

def u32(d, o): return struct.unpack_from('<I', d, o)[0]
def u64(d, o): return struct.unpack_from('<Q', d, o)[0]
def p32(d, o, v): struct.pack_into('<I', d, o, v)
def p64(d, o, v): struct.pack_into('<Q', d, o, v)

NOP = 0xD503201F
MOV_X0_0 = 0xD2800000

def adrp_target(insn, pc):
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20): imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)

def add_imm(insn):
    imm = (insn >> 10) & 0xFFF
    if (insn >> 22) & 1: imm <<= 12
    return imm

def enc_adrp(rd, pc, target):
    delta = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    if not -(1 << 20) <= delta < (1 << 20): raise ValueError("adrp range")
    delta &= (1 << 21) - 1
    return 0x90000000 | ((delta & 3) << 29) | ((delta >> 2) << 5) | rd

def enc_add_imm(rd, rn, imm):
    assert 0 <= imm < 0x1000
    return 0x91000000 | (imm << 10) | (rn << 5) | rd

def find_all(d, needle):
    out, i = [], 0
    while True:
        i = d.find(needle, i)
        if i < 0: return out
        out.append(i); i += 1

def adrp_add_refs(d, target_off):
    """file offsets of ADRP Xn ; ADD Xn,Xn,#imm pairs (within 4 insns) that materialise target"""
    refs = []
    for off in range(0, len(d) - 8, 4):
        insn = u32(d, off)
        if insn & 0x9F000000 != 0x90000000: continue
        rd = insn & 0x1F
        page = adrp_target(insn, off)
        if page != target_off & ~0xFFF: continue
        for k in range(1, 5):
            a = u32(d, off + 4 * k)
            if a & 0xFFC00000 == 0x91000000 and (a & 0x1F) == rd and ((a >> 5) & 0x1F) == rd:
                if page + add_imm(a) == target_off:
                    refs.append((off, off + 4 * k))
                break
    return refs

def bcond_target(insn, pc):
    if insn & 0xFF000010 != 0x54000000: return None
    imm = (insn >> 5) & 0x7FFFF
    if imm & (1 << 18): imm -= 1 << 19
    return pc + (imm << 2)

# ---------------------------------------------------------------- 1. image4 validate
def patch_validate(d, log):
    anchors = find_all(d, b"Unknown ASN1 type %llu\n\0")
    if len(anchors) != 1: raise SystemExit(f"validate: anchor count {len(anchors)}")
    refs = adrp_add_refs(d, anchors[0])
    cands = set()
    for adrp, _ in refs:
        for off in range(max(0, adrp - 0x800) & ~3, adrp, 4):
            prev, br, mov = u32(d, off - 4), u32(d, off), u32(d, off + 4)
            if prev >> 26 != 0b100101: continue             # BL
            if br & 0xFF00001F != 0x54000001: continue       # B.NE
            if bcond_target(br, off) + 8 != adrp: continue   # failure path materialises anchor
            if mov != 0xAA1403E0: continue                    # MOV X0, X20
            cands.add(off)
    if len(cands) != 1: raise SystemExit(f"validate: candidates {sorted(map(hex, cands))}")
    off = cands.pop()
    p32(d, off, NOP); p32(d, off + 4, MOV_X0_0)
    log.append(f"validate      @0x{off:x}: b.ne -> nop ; mov x0,x20 -> mov x0,#0")

# ---------------------------------------------------------------- 2. boot-args
def patch_bootargs(d, args, log):
    # the original format is "%s" whose argument is iBoot's own dynamic part ("rd=md0[ -progress][ -restore]"
    # when a ramdisk is loaded, else empty) -> keep it in front so ramdisk boots still get rd=md0.
    # (a single leading "%s" is allowed; any other % is rejected)
    if '%' in args.replace('%s', '', 1) or ('%s' in args and not args.startswith('%s')):
        raise SystemExit("boot-args may only contain a leading %s")
    lit = args.encode() + b"\0"
    sites = []
    for off in range(0, len(d) - 20, 4):
        adrp, add, dst, cap, call = (u32(d, off + 4 * i) for i in range(5))
        if adrp & 0x9F00001F != 0x90000002: continue
        if add & 0xFFC003FF != 0x91000042: continue
        if not (dst & 0xFFC003FF == 0x910003E0 or dst & 0xFFC003FF == 0xD10003A0): continue
        if cap != 0x52808001: continue
        if call >> 26 != 0b100101: continue
        fmt = adrp_target(adrp, off) + add_imm(add)
        if d[fmt:fmt + 3] == b"%s\0" and d[fmt - 1] == 0:
            sites.append(off)
    if len(sites) != 1: raise SystemExit(f"bootargs: sites {list(map(hex, sites))}")
    site = sites[0]
    # find a zero run at the tail of a 4K page in __TEXT cstring/const area (before data)
    need = len(lit) + 16
    text_end = _layout.TEXT_END  # file offset where data starts (from the iBoot header)
    slot = None
    for page_end in range(0x1000, text_end + 1, 0x1000):
        start = page_end - need
        if start < 0x1000: continue
        if d[start:page_end] == b"\0" * need:
            # make sure the zero run really extends (padding, not a string terminator run)
            slot = (start + 0xF) & ~0xF
            if slot + len(lit) <= page_end: break
            slot = None
    if slot is None: raise SystemExit("bootargs: no slot")
    p32(d, site, enc_adrp(2, site, slot))
    p32(d, site + 4, enc_add_imm(2, 2, slot & 0xFFF))
    d[slot:slot + len(lit)] = lit
    log.append(f"boot-args     @0x{site:x}: format -> 0x{slot:x} \"{args}\"")
    return slot

# ---------------------------------------------------------------- 3. memboot -> fsboot
def find_cmd_entry(d, name, table_lo, table_hi):
    """entry layout: [name*, name*, next_name*, ?, handler(chained), ...] ; returns file off of entry"""
    hits = []
    for s in find_all(d, name.encode() + b"\0"):
        if s > 0 and d[s - 1] != 0: continue
        va = BASE + s
        for off in range(table_lo, table_hi, 8):
            if u64(d, off) == va and u64(d, off + 8) == va:
                hits.append(off)
    return hits

def patch_fsboot_cmd(d, log):
    # boot-command table (data region) holds the fsboot entry; console table holds memboot
    fs = [e for e in find_cmd_entry(d, "fsboot", 0x100000, len(d) - 0x40)]
    mb = [e for e in find_cmd_entry(d, "memboot", 0x100000, len(d) - 0x40)]
    # handlers are at +0x20 ; console table entries have a "next" name ptr at +0x10
    def handler(e): return u64(d, e + 0x20)
    fs = [e for e in fs if handler(e) >> 63 == 1 and (handler(e) & 0xFFFFFFFF) < len(d)]
    mb = [e for e in mb if handler(e) >> 63 == 1 and (handler(e) & 0xFFFFFFFF) < len(d)]
    if len(fs) != 1 or len(mb) != 1:
        raise SystemExit(f"fsboot cmd: fs={list(map(hex, fs))} mb={list(map(hex, mb))}")
    fs_h, mb_h = handler(fs[0]), handler(mb[0])
    # chained auth ptr: keep auth/key/addrDiv/diversity/next bits of the memboot slot, swap target
    if (fs_h >> 32) & 0x1FFFF or (mb_h >> 32) & 0x1FFFF:
        raise SystemExit("fsboot cmd: pointer uses diversity/addrDiv, refusing")
    new = (mb_h & ~0xFFFFFFFF) | (fs_h & 0xFFFFFFFF)
    p64(d, mb[0] + 0x20, new)
    global MEMBOOT_FN
    MEMBOOT_FN = mb_h & 0xFFFFFFFF
    log.append(f"memboot->fsboot @0x{mb[0]+0x20:x}: 0x{mb_h:x} -> 0x{new:x} (fsboot fn 0x{BASE + (fs_h & 0xFFFFFFFF):x})")

# ---------------------------------------------------------------- 4. pretend local (NAND) boot
def patch_local_boot(d, log, clear_hw=False, cave=None):
    """platform_is_remote_boot(): MOV X8,#0x23B0B8000 ; LDR W8,[X8] ; UBFX W0,W8,#5,#1 ; RET
    -> force 0 so iBoot loads NVRAM / nonce generator and behaves like a NAND boot."""
    pat = bytes.fromhex("080090d26861a7f24800c0f2080140b900150553c0035fd6")
    hits = find_all(d, pat)
    if len(hits) != 1: raise SystemExit(f"local-boot: hits {list(map(hex, hits))}")
    off = hits[0] + 16
    if not clear_hw:
        p32(d, off, 0x52800000)  # mov w0, #0
        log.append(f"remote-boot -> local @0x{off:x}")
        return
    # rewrite: x8=0x23B0B8000 (kept), w9=[x8]; w9&=~0x20; [x8]=w9; mov w0,#0; ret  -> needs 2 extra words,
    # so branch to a cave that holds the full body.
    body = [0xD2900008, 0xF2A76168, 0xF2C00048,   # mov x8,#0x23B0B8000
            0xB9400109,                            # ldr w9,[x8]
            0x121A7929,                            # and w9,w9,#~0x20
            0xB9000109,                            # str w9,[x8]
            0xD5033F9F,                            # dsb sy
            0x52800000,                            # mov w0,#0
            0xD65F03C0]                            # ret
    for i, w in enumerate(body): p32(d, cave + 4 * i, w)
    rel = (cave - hits[0]) >> 2
    p32(d, hits[0], 0x14000000 | (rel & 0x3FFFFFF))
    log.append(f"remote-boot -> local + clear HW bit5 @0x{hits[0]:x} -> cave 0x{cave:x}")

# ---------------------------------------------------------------- 5. never auto-boot (stay at console)
def patch_no_autoboot(d, log):
    """autoboot(): x27 = env_get_bool("auto-boot", ...) -> x27 = 0, so iBoot drops to the recovery
    console even in local-boot mode, letting the host upload ramdisk/payloads before `memboot`."""
    strs = [s for s in find_all(d, b"auto-boot\0") if d[s - 1] == 0]
    cands = []
    for s in strs:
        for adrp, add in adrp_add_refs(d, s):
            for k in range(1, 10):
                o = add + 4 * k
                if u32(d, o) >> 26 == 0b100101 and u32(d, o + 4) == 0xAA0003FB:  # BL ; MOV X27,X0
                    cands.append(o + 4); break
    cands = sorted(set(cands))
    if len(cands) != 1: raise SystemExit(f"no-autoboot: {list(map(hex, cands))}")
    p32(d, cands[0], 0xD280001B)  # mov x27, #0
    log.append(f"auto-boot -> false @0x{cands[0]:x}")

def patch_no_sep(d, log):
    """SEP-less: fsboot skips loading sep-firmware (as if already loaded). Finds the unique
    `BL sep_loaded(); TBNZ W0,#0,skip` where sep_loaded = ldr global; cmp; ldr [+0x20]; ccmp; cset; ret."""
    pred = [o for o in range(0, len(d) - 32, 4) if u32(d, o) & 0x9F00001F == 0x90000008
            and u32(d, o + 8) == 0xF9400109 and u32(d, o + 12) == 0xF100013F and u32(d, o + 16) == 0xF9401108
            and u32(d, o + 20) == 0xFA401904 and u32(d, o + 24) == 0x1A9F07E0 and u32(d, o + 28) == 0xD65F03C0]
    if len(pred) != 1: raise SystemExit(f"no-sep: predicate {list(map(hex, pred))}")
    hits = []
    for o in range(0, len(d) - 8, 4):
        w = u32(d, o)
        if w >> 26 == 0x25 and o + (((w & 0x3FFFFFF) ^ 0x2000000) - 0x2000000) * 4 == pred[0]:
            t = u32(d, o + 4)
            if t & 0xFFF8001F == 0x37000000: hits.append((o + 4, t))
    if len(hits) != 1: raise SystemExit(f"no-sep: sites {hits}")
    site, t = hits[0]
    imm14 = (t >> 5) & 0x3FFF
    d[site:site + 4] = struct.pack("<I", 0x14000000 | imm14)   # same displacement, unconditional
    log.append(f"no-sep        @0x{site:x}: tbnz w0,#0 -> b (+0x{imm14 * 4:x}), sep-firmware not loaded")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inp"); ap.add_argument("out")
    ap.add_argument("--boot-args", default="-v serial=3 debug=0x2014e wdt=-1")
    ap.add_argument("--no-fsboot", action="store_true")
    ap.add_argument("--local", action="store_true", help="force local-boot behaviour (NVRAM, auto-boot)")
    ap.add_argument("--clear-remote", action="store_true", help="also clear the remote-boot bit in hardware")
    ap.add_argument("--no-autoboot", action="store_true", help="never auto-boot; stay at recovery console")
    ap.add_argument("--rd-rename", action="store_true", help='make iBoot pass "jb=md0" instead of "rd=md0"')
    ap.add_argument("--svc-copy", action="store_true", help="install EL1 SVC #9 physical copy stub")
    ap.add_argument("--exc-hook", action="store_true", help="print ESR/FAR/ELR on iBoot exceptions")
    ap.add_argument("--entry-src", default="kpf_entry.S", help="assembly for the boot_kernel entry hook")
    ap.add_argument("--entry-hook", action="store_true", help="patch at boot_kernel entry (before layout/lock)")
    ap.add_argument("--sepless", action="store_true", help="keep kernel.aks.*/kernel.sep.* records (SEP-less userland; SEP firmware still loaded)")
    ap.add_argument("--no-sep-load", action="store_true", help="skip loading sep-firmware (PANICS later in iBoot TZ setup 0x11cafc:530 - do not use)")
    ap.add_argument("--keep-cmds", action="store_true", help="never use the go / rsepfirmware bodies as caves (the iBSS->iBEC->bootx chain needs them)")
    ap.add_argument("--range", action="append", default=[], metavar="LO:HI", help="search range per --kpf (0:0 = kernel buffer)")
    ap.add_argument("--hook-src", default="kpf_hook.S", help="assembly for the prepare_and_jump hook")
    ap.add_argument("--kpf", action="append", default=[], metavar="RAW:JSON[,JSON...]",
                    help="patch a Mach-O image in RAM before prepare_and_jump (repeatable)")
    a = ap.parse_args()
    d = bytearray(open(a.inp, "rb").read())
    if b"mBoot-" not in d[0x300:0x320] and b"iBoot-" not in d[0x300:0x320]:
        raise SystemExit("not a raw iBoot")
    global BASE
    BASE, _ = _layout.set_layout(d)
    log = []
    patch_validate(d, log)
    slot = patch_bootargs(d, a.boot_args, log)
    if not a.no_fsboot: patch_fsboot_cmd(d, log)
    if a.local and not a.clear_remote: patch_local_boot(d, log)
    if a.no_autoboot: patch_no_autoboot(d, log)
    if a.no_sep_load: patch_no_sep(d, log)
    if a.rd_rename:
        hits = [s for s in find_all(d, b"rd=md0\0") if d[s - 1] == 0]
        if len(hits) != 1: raise SystemExit(f"rd=md0: {hits}")
        if len(adrp_add_refs(d, hits[0])) != 1: raise SystemExit("rd=md0: expected exactly one reference")
        d[hits[0]:hits[0] + 2] = b"jb"
        log.append(f"ramdisk arg   @0x{hits[0]:x}: \"rd=md0\" -> \"jb=md0\"")
    if a.kpf or a.hook_src != "kpf_hook.S" or a.entry_hook:
        import kpf
        if a.no_fsboot: raise SystemExit("--kpf needs the memboot->fsboot swap (table lives in memboot)")
        images = []
        for spec in a.kpf:
            raw, js = spec.split(":", 1)
            img = open(raw, "rb").read()
            recs = kpf.load_records(js.split(","), exclude_prefixes=("kernel.identity",) if a.sepless else ("kernel.identity", "kernel.aks."))
            words = kpf.records_to_words(img, recs)
            anchor = kpf.segment_fileoff(img, "__TEXT_EXEC")
            if any(o < anchor for o, _, _ in words):
                anchor = 0          # patches before __TEXT_EXEC (e.g. __cstring): anchor on the Mach-O header
            images.append((img, words, anchor))
        start = slot
        while d[start - 4:start] == b"\0\0\0\0": start -= 4
        code_off = (start + 0x10) & ~0xF
        go = find_cmd_entry(d, "go", 0x100000, len(d) - 0x40)
        go = [e for e in go if u64(d, e + 0x20) >> 63 == 1]
        extra = []
        if len(go) == 1 and not a.keep_cmds:
            go_fn = u64(d, go[0] + 0x20) & 0xFFFFFFFF
            if u32(d, go_fn) == 0xD503237F:
                extra.append((go_fn, _layout.handler_size(d, go_fn)))
        rs = [e for e in find_cmd_entry(d, "rsepfirmware", 0x100000, len(d) - 0x40) if u64(d, e + 0x20) >> 63 == 1]
        if len(rs) == 1 and a.entry_hook and not a.keep_cmds:
            rs_fn = u64(d, rs[0] + 0x20) & 0xFFFFFFFF
            if u32(d, rs_fn) == 0xD503237F:
                extra.append((rs_fn, _layout.handler_size(d, rs_fn)))   # rsepfirmware body: unused in the jailbreak flow
                # the table entries stay: with their bodies used as caves, never send go/rsepfirmware (--keep-cmds)
        if a.sepless and a.entry_hook:
            sp = [e for e in find_cmd_entry(d, "setpicture", 0x100000, len(d) - 0x40) if u64(d, e + 0x20) >> 63 == 1]
            if len(sp) == 1:
                sp_fn = u64(d, sp[0] + 0x20) & 0xFFFFFFFF
                dt = [e for e in find_cmd_entry(d, "devicetree", 0x100000, len(d) - 0x40) if u64(d, e + 0x20) >> 63 == 1]
                end = (u64(d, dt[0] + 0x20) & 0xFFFFFFFF) if len(dt) == 1 else 0
                if u32(d, sp_fn) == 0xD503237F and sp_fn < end <= sp_fn + 0x400:
                    extra.append((sp_fn, end - sp_fn))   # setpicture body: unused in the jailbreak flow
                    log.append(f"cave: setpicture body 0x{sp_fn:x}+0x{end - sp_fn:x}")
        if a.entry_hook:
            regions = [[MEMBOOT_FN, MEMBOOT_FN + _layout.handler_size(d, MEMBOOT_FN)], [code_off, slot]] + [[o, o + n] for o, n in extra]
            imgs, slots = [], []
            for i, (img, words, anchor) in enumerate(images):
                rng = a.range[i] if i < len(a.range) else "0:0"
                if rng.startswith("slot"):           # e.g. slot0 = TXM, slot2 = SPTM
                    slots.append((img, words, anchor, int(rng[4:])))
                else:
                    lo, hi = (int(x, 16) for x in rng.split(":"))
                    imgs.append((img, words, anchor, lo, hi))
            # TXM/SPTM records use offsets from the image start (no anchor-relative rebasing)
            kpf.install_entry(d, log, imgs, find_all, adrp_add_refs, regions, a.entry_src)
            for img, words, anchor, idx in slots:
                kpf.install_slot(d, log, img, words, anchor, idx, find_all, adrp_add_refs, regions)
            if a.exc_hook:
                kpf.install_exc(d, log, find_all, adrp_add_refs, regions)
            if a.svc_copy:
                kpf.install_svc_handler(d, log)
            if a.clear_remote:
                for r in regions:
                    s = (r[0] + 15) & ~15
                    if s + 36 <= r[1]:
                        r[0] = s + 36; patch_local_boot(d, log, True, s); break
                else:
                    raise SystemExit("no space for clear-remote cave")
        else:
            used = kpf.install(d, log, images, find_all, adrp_add_refs, MEMBOOT_FN, code_off, slot, a.hook_src, extra)
            if a.clear_remote:
                patch_local_boot(d, log, True, (code_off + used + 0xF) & ~0xF)
    open(a.out, "wb").write(d)
    print("\n".join(log))

if __name__ == "__main__":
    main()
