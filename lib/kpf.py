#!/usr/bin/env python3
"""
In-RAM KPF injection for iBoot (T8030 / iOS 27.2).

Builds a patch table from JSON patch records (offset/originalBytes/replacementBytes)
for one or more Mach-O images (kernelcache, TXM, ...), assembles kpf_hook.S and installs both into a
raw iBoot image:
  * table  -> the body of the original `memboot` console handler (unreachable once memboot is
              repointed to fsboot by patch_iboot.py)
  * code   -> executable page-tail padding after the last function of a code page
  * hook   -> the `BL prepare_and_jump` with W0=#3 in the common boot path (bootx/fsboot/memboot)

Images are located at runtime by their 32-byte Mach-O header, so the same table works no matter
where iBoot placed them. Only images whose header bytes come from the very same build as the
on-disk (or uploaded) image will ever be patched; every original word is checked first.
"""
import json, os, struct, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = 0x19C050000      # iBoot load address  - replaced by set_layout() from the image header
TEXT_END = 0x1EC000     # file offset of iBoot's data (end of code) - likewise

def set_layout(d):
    """Take iBoot's load address and data start from its own header (T8030 mBoot, iOS 27.0-27.2:
    0x380 = load address, 0x398 = first data address) instead of build-specific constants."""
    global BASE, TEXT_END
    base, data = struct.unpack_from('<Q', d, 0x380)[0], struct.unpack_from('<Q', d, 0x398)[0]
    if base & 0xFFF or data & 0xFFF or not (base < data <= base + len(d)):
        raise SystemExit(f"iBoot header: unexpected layout base=0x{base:x} data=0x{data:x} len=0x{len(d):x}")
    BASE, TEXT_END = base, data - base
    return BASE, TEXT_END

def handler_size(d, fn):
    """Bytes of the function at fn that can be reused once it is unreachable: up to the next PACIBSP, but never
    past a plain RET that follows the last RETAB, which would mean a leaf (non-PAC) function sits in between."""
    if u32(d, fn) != 0xD503237F: raise SystemExit(f"handler 0x{fn:x}: not PACIBSP")
    e = fn + 4
    while e < TEXT_END and u32(d, e) != 0xD503237F: e += 4
    if u32(d, e - 4) == 0xD503245F: e -= 4          # BTI c of the next function
    last_retab = max((o for o in range(fn, e, 4) if u32(d, o) == 0xD65F0FFF), default=None)
    if last_retab is not None and any(u32(d, o) == 0xD65F03C0 for o in range(last_retab, e, 4)):
        e = last_retab + 4
    return e - fn

def u32(d, o): return struct.unpack_from('<I', d, o)[0]

def load_records(paths, exclude_prefixes=()):
    recs = []
    for p in paths:
        j = json.load(open(p))
        for r in (j if isinstance(j, list) else j["records"]):
            if any(r["id"].startswith(x) for x in exclude_prefixes): continue
            recs.append(r)
    return recs

def records_to_words(image, recs):
    """Turn byte-granular records into aligned (off, orig, new) word triples."""
    words = {}
    for r in recs:
        off = r["offset"]; orig = bytes.fromhex(r["originalBytes"]); new = bytes.fromhex(r["replacementBytes"])
        if image[off:off + len(orig)] != orig:
            raise SystemExit(f"{r['id']}: original bytes do not match image at 0x{off:x}")
        for i in range(len(new)):
            a = off + i
            w = a & ~3
            if w not in words:
                words[w] = bytearray(image[w:w + 4])
            words[w][a - w] = new[i]
    out = []
    for w in sorted(words):
        o = u32(image, w); n = struct.unpack('<I', bytes(words[w]))[0]
        if o != n: out.append((w, o, n))
    return out

def build_table(images):
    """images: list of (raw_bytes, [(off,orig,new)...], anchor_off)"""
    t = struct.pack('<I', len(images))
    for raw, words, anchor in images:
        t += raw[anchor:anchor + 32] + struct.pack('<II', len(words), 0)
        for off, o, n in words:
            if off < anchor: raise SystemExit(f"patch 0x{off:x} below anchor 0x{anchor:x}")
            t += struct.pack('<III', off - anchor, o, n)
    return t

def segment_fileoff(raw, segname):
    ncmds = struct.unpack_from('<I', raw, 16)[0]; off = 32
    for _ in range(ncmds):
        cmd, cs = struct.unpack_from('<II', raw, off)
        if cmd == 0x19 and raw[off + 8:off + 24].rstrip(b"\0").decode() == segname:
            return struct.unpack_from('<Q', raw, off + 40)[0]
        off += cs
    raise SystemExit(f"segment {segname} not found")

def assemble(src="kpf_hook.S"):
    with tempfile.TemporaryDirectory() as td:
        obj = os.path.join(td, "hook.o")
        subprocess.run(["clang", "-c", "-target", "arm64-apple-ios", "-o", obj, os.path.join(HERE, src)], check=True)
        out = subprocess.run(["otool", "-l", obj], capture_output=True, text=True, check=True).stdout
        # find __text offset/size
        lines = out.splitlines()
        for i, l in enumerate(lines):
            if l.strip() == "sectname __text":
                kv = {}
                for l2 in lines[i + 1:i + 12]:
                    p = l2.split()
                    if len(p) >= 2 and p[0] not in kv: kv[p[0]] = p[1]
                size = int(kv["size"], 16); offset = int(kv["offset"])
                break
        return open(obj, "rb").read()[offset:offset + size]

def find_printf(d, find_all, adrp_add_refs):
    fmt = [s for s in find_all(d, b"%llx:%d\n\0") if d[s - 1] == 0]
    targets = {}
    for s in fmt:
        for adrp, add in adrp_add_refs(d, s):
            for k in range(1, 7):
                insn = u32(d, add + 4 * k)
                if insn >> 26 == 0b000101:  # B imm26
                    imm = insn & 0x3FFFFFF
                    if imm & (1 << 25): imm -= 1 << 26
                    t = add + 4 * k + (imm << 2)
                    targets[t] = targets.get(t, 0) + 1
                    break
    t = max(targets, key=targets.get)
    if u32(d, t) != 0xD503237F: raise SystemExit("printf: target is not PACIBSP")
    return t

def bl_target(insn, pc):
    imm = insn & 0x3FFFFFF
    if imm & (1 << 25): imm -= 1 << 26
    return pc + (imm << 2)

def find_hook_site(d):
    """LDP X2,X1,[SP,#imm] ; MOV W0,#3 ; BL prepare_and_jump   (unique)"""
    sites = []
    for off in range(0, TEXT_END, 4):
        if u32(d, off) == 0x52800060 and u32(d, off + 4) >> 26 == 0b100101:
            p = u32(d, off - 4)
            if p & 0xFFC07FFF == 0xA94007E2:  # LDP X2, X1, [SP, #imm]
                sites.append(off + 4)
    if len(sites) != 1: raise SystemExit(f"hook site: {list(map(hex, sites))}")
    return sites[0]

def install(d, log, images, find_all, adrp_add_refs, memboot_fn_off, code_off, code_limit, src="kpf_hook.S",
            extra_regions=()):
    """Place hook code + an index + one record per image into free regions:
       memboot handler body, the page-tail cave, plus any extra (off, size) regions."""
    code = bytearray(assemble(src))
    hook_site = find_hook_site(d)
    paj = bl_target(u32(d, hook_site), hook_site)
    printf = find_printf(d, find_all, adrp_add_refs)
    fmt = [s for s in find_all(d, b"%llx:%d\n\0") if d[s - 1] == 0][0]
    if u32(d, memboot_fn_off) != 0xD503237F: raise SystemExit("memboot fn not PACIBSP")
    regions = [[memboot_fn_off, memboot_fn_off + handler_size(d, memboot_fn_off)], [code_off, code_limit]] + [[o, o + n] for o, n in extra_regions]
    def alloc(size, align=8):
        for r in regions:
            s = (r[0] + align - 1) & ~(align - 1)
            if s + size <= r[1]:
                r[0] = s + size
                return s
        raise SystemExit(f"no space for {size} bytes")
    code_at = alloc(len(code), 16)
    records = []
    for raw, words, anchor in images:
        rec = raw[anchor:anchor + 32] + struct.pack('<II', len(words), 0)
        for off, o, n in words: rec += struct.pack('<III', off - anchor, o, n)
        records.append(rec)
    rec_at = [alloc(len(r)) for r in records]
    index = struct.pack('<II', len(records), 0) + b"".join(struct.pack('<Q', BASE + a) for a in rec_at)
    index_at = alloc(len(index))
    for ph, val in ((0x1111111111111111, BASE + index_at), (0x2222222222222222, BASE + printf),
                    (0x3333333333333333, BASE + paj), (0x4444444444444444, BASE + fmt)):
        i = code.find(struct.pack('<Q', ph))
        if i < 0: raise SystemExit("placeholder missing")
        code[i:i + 8] = struct.pack('<Q', val)
    d[code_at:code_at + len(code)] = code
    for a, r in zip(rec_at, records): d[a:a + len(r)] = r
    d[index_at:index_at + len(index)] = index
    rel = (code_at - hook_site) >> 2
    d[hook_site:hook_site + 4] = struct.pack('<I', 0x94000000 | (rel & 0x3FFFFFF))
    n = sum(len(w) for _, w, _a in images)
    log.append(f"kpf hook      @0x{hook_site:x}: BL prepare_and_jump(0x{BASE+paj:x}) -> hook 0x{BASE+code_at:x} "
               f"({len(code)} B code, records {[hex(BASE+a) for a in rec_at]}, {len(images)} images, {n} words)")
    return regions[1][0] - code_off  # bytes consumed in the cave


def find_boot_kernel(d):
    """boot_kernel(): the routine containing `LDP X2,X1,[SP,#imm] ; MOV W0,#3 ; BL prepare_and_jump`.
    Walk back from the hook site to the nearest `PACIBSP ; SUB SP,SP,#imm` prologue."""
    site = find_hook_site(d)
    off = site
    while off > 0:
        off -= 4
        if u32(d, off) == 0xD503237F and u32(d, off + 4) & 0xFFC003FF == 0xD10003FF:  # PACIBSP ; SUB SP,SP,#imm
            return off
    raise SystemExit("boot_kernel entry not found")

def install_entry(d, log, images, find_all, adrp_add_refs, regions, src="kpf_entry.S"):
    """images: list of (raw, words, anchor_off, lo, hi)"""
    code = bytearray(assemble(src))
    entry = find_boot_kernel(d)
    printf = find_printf(d, find_all, adrp_add_refs)
    fmt = [s for s in find_all(d, b"%llx:%d\n\0") if d[s - 1] == 0][0]
    def alloc(size, align=8):
        for r in regions:
            s = (r[0] + align - 1) & ~(align - 1)
            if s + size <= r[1]:
                r[0] = s + size; return s
        raise SystemExit(f"no space for {size} bytes")
    recs = []
    for raw, words, anchor, lo, hi in images:
        r = raw[anchor:anchor + 32] + struct.pack('<IIQQ', len(words), 0, lo, hi)
        for off, o, n in words: r += struct.pack('<III', off - anchor, o, n)
        recs.append(r)
    # place biggest blobs first (first-fit decreasing)
    items = sorted([("code", len(code))] + [(i, len(r)) for i, r in enumerate(recs)], key=lambda t: -t[1])
    where = {}
    for key, size in items: where[key] = alloc(size, 16 if key == "code" else 8)
    code_at = where["code"]; rec_at = [where[i] for i in range(len(recs))]
    index = struct.pack('<II', len(recs), 0) + b"".join(struct.pack('<Q', BASE + a) for a in rec_at)
    index_at = alloc(len(index))
    for ph, val in ((0x1111111111111111, BASE + index_at), (0x2222222222222222, BASE + printf),
                    (0x3333333333333333, BASE + entry + 4), (0x4444444444444444, BASE + fmt)):
        i = code.find(struct.pack('<Q', ph))
        if i < 0: continue
        code[i:i + 8] = struct.pack('<Q', val)
    mk = code.find(struct.pack('<I', 0xD4224680))   # brk #0x1234
    if mk < 0 or mk % 4: raise SystemExit("return marker missing")
    rel = ((entry + 4) - (code_at + mk)) >> 2
    code[mk:mk + 4] = struct.pack('<I', 0x14000000 | (rel & 0x3FFFFFF))      # B routine+4
    d[code_at:code_at + len(code)] = code
    for a, r in zip(rec_at, recs): d[a:a + len(r)] = r
    d[index_at:index_at + len(index)] = index
    rel = (code_at - entry) >> 2
    d[entry:entry + 4] = struct.pack('<I', 0x14000000 | (rel & 0x3FFFFFF))   # B hook
    n = sum(len(i[1]) for i in images)
    log.append(f"kpf entry hook @0x{entry:x} (boot_kernel 0x{BASE+entry:x}) -> 0x{BASE+code_at:x} "
               f"({len(code)} B code, {len(images)} images, {n} words, records {[hex(BASE+a) for a in rec_at]})")


def find_slot_site(d):
    """In the SPTM/TXM/CL4 loader: BL memcpy ; LSL W8,W28,#5 ; ORR W9,W8,W28,LSL#7 ; BL slot_table"""
    pat = bytes.fromhex("886b1b53" "091d1c2a")
    hits = []
    i = 0
    while True:
        i = d.find(pat, i)
        if i < 0: break
        if i % 4 == 0 and u32(d, i - 4) >> 26 == 0b100101 and u32(d, i + 8) >> 26 == 0b100101:
            hits.append(i)
        i += 1
    if len(hits) != 1: raise SystemExit(f"slot site: {list(map(hex, hits))}")
    return hits[0]

def install_slot(d, log, raw, words, anchor, slot_index, find_all, adrp_add_refs, regions, src="kpf_slot.S"):
    code = bytearray(assemble(src))
    site = find_slot_site(d)
    printf = find_printf(d, find_all, adrp_add_refs)
    fmt = [s for s in find_all(d, b"%llx:%d\n\0") if d[s - 1] == 0][0]
    rec = struct.pack('<II', slot_index, len(words)) + raw[anchor:anchor + 32] + struct.pack('<II', anchor, 0)
    for off, o, n in words: rec += struct.pack('<III', off, o, n)
    def alloc(size, align):
        for r in regions:
            s = (r[0] + align - 1) & ~(align - 1)
            if s + size <= r[1]:
                r[0] = s + size; return s
        raise SystemExit(f"no space for {size} bytes")
    rec_at = alloc(len(rec), 8); code_at = alloc(len(code), 16)
    for ph, val in ((0x1111111111111111, BASE + rec_at), (0x2222222222222222, BASE + printf),
                    (0x4444444444444444, BASE + fmt)):
        i = code.find(struct.pack('<Q', ph)); code[i:i + 8] = struct.pack('<Q', val)
    d[code_at:code_at + len(code)] = code
    d[rec_at:rec_at + len(rec)] = rec
    rel = (code_at - site) >> 2
    d[site:site + 4] = struct.pack('<I', 0x94000000 | (rel & 0x3FFFFFF))   # BL hook
    log.append(f"kpf slot hook @0x{site:x} (slot {slot_index}) -> 0x{BASE+code_at:x} ({len(code)} B code, {len(words)} words, record 0x{BASE+rec_at:x})")


def install_exc(d, log, find_all, adrp_add_refs, regions, src="exc_hook.S"):
    """BL exc_hook in place of `MRS X8, ESR_EL1` in iBoot's exception handler (MOV X19,X0 ; MRS X8,ESR ; MRS X9,FAR)."""
    pat = bytes.fromhex("f30300aa085238d5096038d5")
    hits = [i for i in range(0, len(d) - 12, 4) if d[i:i + 12] == pat]
    if len(hits) != 1: raise SystemExit(f"exc site: {list(map(hex, hits))}")
    site = hits[0] + 4
    code = bytearray(assemble(src))
    printf = find_printf(d, find_all, adrp_add_refs)
    fmt = [s for s in find_all(d, b"%llx:%d\n\0") if d[s - 1] == 0][0]
    for ph, val in ((0x2222222222222222, BASE + printf), (0x4444444444444444, BASE + fmt)):
        i = code.find(struct.pack('<Q', ph)); code[i:i + 8] = struct.pack('<Q', val)
    at = None
    for r in regions:
        s = (r[0] + 15) & ~15
        if s + len(code) <= r[1]:
            at = s; r[0] = s + len(code); break
    if at is None: raise SystemExit("no space for exc hook")
    d[at:at + len(code)] = code
    rel = (at - site) >> 2
    d[site:site + 4] = struct.pack('<I', 0x94000000 | (rel & 0x3FFFFFF))
    log.append(f"exc hook      @0x{site:x} -> 0x{BASE+at:x} ({len(code)} B)")


def install_svc(d, log, regions, number=9, src="svc_copy.S"):
    """Point SVC #number (an unused dispatcher case) at an EL1 stub. Dispatcher shape:
         ADRL X17, jpt ; LDRSW X16, [X17, X16, LSL#2] ; ADR X17, base ; ADD X16, X17, X16 ; BR X16"""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    hits = [o for o in range(0x10, TEXT_END, 4) if u32(d, o) == 0xB8B07A30 and u32(d, o + 12) == 0xD61F0200
            and u32(d, o - 0x10) == 0xF103861F]   # CMP X16, #0xE1 (226-case SVC dispatcher)
    if len(hits) != 1: raise SystemExit(f"svc dispatcher: {list(map(hex, hits))}")
    ldrsw = hits[0]
    adrp, add = u32(d, ldrsw - 8), u32(d, ldrsw - 4)
    def adrp_t(insn, pc):
        imm = ((insn >> 5) & 0x7FFFF) << 2 | ((insn >> 29) & 3)
        if imm & (1 << 20): imm -= 1 << 21
        return (pc & ~0xFFF) + (imm << 12)
    jpt = adrp_t(adrp, ldrsw - 8) + ((add >> 10) & 0xFFF)
    adr = u32(d, ldrsw + 4)
    imm = ((adr >> 5) & 0x7FFFF) << 2 | ((adr >> 29) & 3)
    if imm & (1 << 20): imm -= 1 << 21
    base = ldrsw + 4 + imm
    def target(n):
        rel = struct.unpack_from('<i', d, jpt + 4 * n)[0]
        return base + rel
    # common return: first unconditional B in case 16's block
    t16 = target(16); ret = None
    for i in md.disasm(bytes(d[t16:t16 + 0x40]), t16):
        if i.mnemonic == 'b': ret = int(i.op_str.lstrip('#'), 16); break
    if ret is None: raise SystemExit("svc common return not found")
    default = target(9)
    if target(18) != default: raise SystemExit("case 9 is not the default case")
    code = bytearray(assemble(src))
    at = None
    for r in regions:
        s = (r[0] + 15) & ~15
        if s + len(code) <= r[1]: at = s; r[0] = s + len(code); break
    if at is None: raise SystemExit("no space for svc stub")
    mk = code.find(struct.pack('<I', 0xD4224680))
    code[mk:mk + 4] = struct.pack('<I', 0x14000000 | (((ret - (at + mk)) >> 2) & 0x3FFFFFF))
    d[at:at + len(code)] = code
    struct.pack_into('<i', d, jpt + 4 * number, at - base)
    log.append(f"svc #{number}     jpt 0x{BASE+jpt:x} base 0x{BASE+base:x}: default 0x{BASE+default:x} -> stub 0x{BASE+at:x} ({len(code)} B), return 0x{BASE+ret:x}")


def install_svc_handler(d, log, number=16, src="svc_copy.S"):
    """Overwrite the EL1 handler of an SVC that EL0 never issues (case `number` of the 226-case dispatcher:
    MOV X0,X23 ; MOV X1,X22 ; BL handler ; B common_return) with our stub (must end in RET)."""
    hits = [o for o in range(0x10, TEXT_END, 4) if u32(d, o) == 0xB8B07A30 and u32(d, o + 12) == 0xD61F0200
            and u32(d, o - 0x10) == 0xF103861F]
    if len(hits) != 1: raise SystemExit("svc dispatcher not found")
    ldrsw = hits[0]; adrp, add = u32(d, ldrsw - 8), u32(d, ldrsw - 4)
    imm = ((adrp >> 5) & 0x7FFFF) << 2 | ((adrp >> 29) & 3)
    if imm & (1 << 20): imm -= 1 << 21
    jpt = ((ldrsw - 8) & ~0xFFF) + (imm << 12) + ((add >> 10) & 0xFFF)
    adr = u32(d, ldrsw + 4); imm = ((adr >> 5) & 0x7FFFF) << 2 | ((adr >> 29) & 3)
    if imm & (1 << 20): imm -= 1 << 21
    base = ldrsw + 4 + imm
    blk = base + struct.unpack_from('<i', d, jpt + 4 * number)[0]
    if not (u32(d, blk) == 0xAA1703E0 and u32(d, blk + 4) == 0xAA1603E1 and u32(d, blk + 8) >> 26 == 0b100101):
        raise SystemExit(f"case {number} block shape unexpected @0x{blk:x}")
    insn = u32(d, blk + 8); rel = insn & 0x3FFFFFF
    if rel & (1 << 25): rel -= 1 << 26
    fn = blk + 8 + (rel << 2)
    # function size: up to the next PACIBSP
    end = fn + 4
    while u32(d, end) != 0xD503237F: end += 4
    code = assemble(src)
    # make sure nothing else branches into the bytes we overwrite (shared epilogues past them are fine)
    for o in range(0, TEXT_END, 4):
        w = u32(d, o)
        if w >> 26 in (0b100101, 0b000101) and o != blk + 8:
            r = w & 0x3FFFFFF
            if r & (1 << 25): r -= 1 << 26
            if fn <= o + (r << 2) < fn + len(code): raise SystemExit(f"handler 0x{fn:x} is also reached from 0x{o:x}")
    if len(code) > end - fn: raise SystemExit(f"stub {len(code)} > handler {end-fn}")
    d[fn:fn + len(code)] = code
    log.append(f"svc #{number}    handler 0x{BASE+fn:x} ({end-fn} B) <- EL1 copy stub ({len(code)} B)")
