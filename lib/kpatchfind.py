#!/usr/bin/env python3
"""Semantic patch finder for the dualboot-specific kernel patches (ramdisk boot, SEP-less OS B fixes).

Offsets are outputs, never inputs : every site is rediscovered in the kernelcache in front
of us from strings, cross references and instruction shape, every match must be unique, and the original bytes
are recorded so kpf.records_to_words / the in-iBoot KPF keep verifying them before writing.

Patch sets
  ramdisk  (OS B / jbinit ramdisk boot)
    kernel.mount.union-1     __mac_mount: TBNZ Wflags,#5 (MNT_UNION -> EPERM)            -> NOP
    kernel.mount.rootfs      __mac_mount: LDRB Wt,[mp,#mnt_flag+1] ; TBNZ Wt,#6 (MNT_ROOTFS) -> MOV Xt,XZR
    kernel.mount.union-2     __mac_mount: TBZ Wflags,#5 back to after union-1               -> B (same target)
    kernel.rootdev.rename    XNU "rd" boot-arg string used by bsd_init (also refs "md0")   -> "jb"
    kernel.apfs.rd.rename    APFS "rd" boot-arg string used next to "rootdev"              -> "jb"
  osb      (SEP-less OS B)
    kernel.sep.<name>.no-panic        every AppleSEPUserClient REQUIRE(!booted) panic stub (hilo update timer,
                                      Lynx get CPSN / pub key on 27.2): the B.EQ into it      -> NOP
    kernel.aks.sep-booted.false.0/1   AppleSEPKeyStore's only "sep-booted" reader: PACIBSP ; SUB SP -> MOV W0,#0 ; RET
    kernel.sep.sleep.sep-not-alive.0/1 AppleSEPManager::_setPowerState sleep path:
                                      CBZ W8 ; LDR W8,[Xn] ; CMP W8,#2 ; B.NE  -> CMP W8,#7 ; B.GE

usage: kpatchfind.py <kernelcache raw or IM4P> {ramdisk|osb} [-o out.json]
"""
import json, os, struct, sys

# ------------------------------------------------------------------------------------------------ Mach-O
LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035
PACIBSP = 0xD503237F
BTI_C = 0xD503245F
NOP = 0xD503201F
RET = 0xD65F03C0


def u32(d, o): return struct.unpack_from('<I', d, o)[0]
def u64(d, o): return struct.unpack_from('<Q', d, o)[0]


class Image:
    """One Mach-O inside a fileset kernelcache (or the whole file when it is not a fileset)."""
    def __init__(self, kc, name, hdr_off):
        self.kc, self.name, self.sections = kc, name, {}
        d = kc.d
        if u32(d, hdr_off) != 0xFEEDFACF: raise ValueError(f"{name}: no Mach-O header at 0x{hdr_off:x}")
        ncmds = u32(d, hdr_off + 0x10); o = hdr_off + 0x20
        for _ in range(ncmds):
            cmd, size = u32(d, o), u32(d, o + 4)
            if cmd == LC_SEGMENT_64:
                nsect = u32(d, o + 0x40)
                for i in range(nsect):
                    s = o + 0x48 + i * 0x50
                    sect = d[s:s + 16].split(b'\0')[0].decode()
                    seg = d[s + 16:s + 32].split(b'\0')[0].decode()
                    addr, sz, off = u64(d, s + 0x20), u64(d, s + 0x28), u32(d, s + 0x30)
                    self.sections[(seg, sect)] = (addr, off, sz)
            o += size

    def sect(self, seg, sect):
        if (seg, sect) not in self.sections: raise SystemExit(f"{self.name}: no {seg},{sect}")
        return self.sections[(seg, sect)]

    def text(self):
        return self.sect('__TEXT_EXEC', '__text')

    def cstrings(self, s):
        """VAs of the exact NUL-terminated string s (also NUL-preceded) in __TEXT,__cstring."""
        va, off, sz = self.sect('__TEXT', '__cstring')
        d, pat, out = self.kc.d, s.encode() + b'\0', []
        i = off
        while True:
            i = d.find(pat, i, off + sz)
            if i < 0: break
            if i == off or d[i - 1] == 0: out.append(va + (i - off))
            i += 1
        return out

    def cstring_prefix(self, prefix):
        va, off, sz = self.sect('__TEXT', '__cstring')
        d, pat, out = self.kc.d, prefix.encode(), []
        i = off
        while True:
            i = d.find(pat, i, off + sz)
            if i < 0: break
            if i == off or d[i - 1] == 0: out.append(va + (i - off))
            i += 1
        return out


class Kernelcache:
    def __init__(self, data):
        self.d = data
        if u32(data, 0) != 0xFEEDFACF: raise SystemExit("kernelcache: not a 64-bit Mach-O (decompress the IM4P first)")
        self.images = {}
        ncmds = u32(data, 0x10); o = 0x20
        for _ in range(ncmds):
            cmd, size = u32(data, o), u32(data, o + 4)
            if cmd == LC_FILESET_ENTRY:
                fileoff = u64(data, o + 0x10); name_off = u32(data, o + 0x18)
                name = data[o + name_off:o + size].split(b'\0')[0].decode()
                self.images[name] = Image(self, name, fileoff)
            o += size
        if not self.images: raise SystemExit("kernelcache: not a fileset kernelcache")
        # one linear VA<->file mapping per image section; collect all for translation
        self._map = sorted({(a, f, s) for im in self.images.values() for (a, f, s) in im.sections.values() if s})

    def img(self, name):
        if name not in self.images: raise SystemExit(f"kernelcache: no fileset entry {name}")
        return self.images[name]

    def off(self, va):
        for a, f, s in self._map:
            if a <= va < a + s: return f + (va - a)
        raise SystemExit(f"VA 0x{va:x} not mapped")

    def insn(self, va): return u32(self.d, self.off(va))


# ------------------------------------------------------------------------------------------------ decode
def sx(v, bits): return v - (1 << bits) if v & (1 << (bits - 1)) else v

def is_adrp(i): return i & 0x9F000000 == 0x90000000
def adrp_page(i, pc):
    imm = ((i >> 5) & 0x7FFFF) << 2 | ((i >> 29) & 3)
    return (pc & ~0xFFF) + (sx(imm, 21) << 12)
def is_add_imm64(i): return i & 0xFF800000 == 0x91000000
def add_imm(i): return ((i >> 10) & 0xFFF) << (12 if (i >> 22) & 1 else 0)
def is_bl(i): return i & 0xFC000000 == 0x94000000
def bl_target(i, pc): return pc + (sx(i & 0x3FFFFFF, 26) << 2)
def is_bcond(i): return i & 0xFF000010 == 0x54000000
def bcond_target(i, pc): return pc + (sx((i >> 5) & 0x7FFFF, 19) << 2)
def is_tb(i): return i & 0x7E000000 == 0x36000000           # TBZ/TBNZ
def tb_bit(i): return ((i >> 31) << 5) | ((i >> 19) & 0x1F)
def tb_target(i, pc): return pc + (sx((i >> 5) & 0x3FFF, 14) << 2)
def tb_nz(i): return (i >> 24) & 1
def is_cbz_w(i): return i & 0xFF000000 == 0x34000000          # CBZ Wt
def cb_target(i, pc): return pc + (sx((i >> 5) & 0x7FFFF, 19) << 2)
def is_ldrb_uimm(i): return i & 0xFFC00000 == 0x39400000
def is_ldr_w_uimm(i): return i & 0xFFC00000 == 0xB9400000
def is_cmp_w_imm(i): return i & 0xFF80001F == 0x7100001F      # SUBS WZR, Wn, #imm (no shift)
def is_cmp_x_reg(i): return i & 0xFFE0FC1F == 0xEB00001F      # SUBS XZR, Xn, Xm


def words_of(kc, im):
    """(text VA, list of instruction words) for im's __text, cached."""
    if not hasattr(im, '_words'):
        va, off, sz = im.text()
        from array import array
        a = array('I'); a.frombytes(kc.d[off:off + sz])
        if sys.byteorder != 'little': a.byteswap()
        im._words = (va, a)
    return im._words


def text_words(kc, im):
    va, a = words_of(kc, im)
    return {va + 4 * k: i for k, i in enumerate(a)}


def adrp_index(kc, im):
    """page -> [(word index, rd)] for every ADRP in im's __text, cached."""
    if not hasattr(im, '_adrp'):
        va, a = words_of(kc, im)
        idx = {}
        for k, i in enumerate(a):
            if i & 0x9F000000 == 0x90000000:
                idx.setdefault(adrp_page(i, va + 4 * k), []).append((k, i & 0x1F))
        im._adrp = idx
    return im._adrp


def xrefs(kc, im, target):
    """ADRP Xd ; ... ; ADD Xd,Xd,#lo (within 4 instructions) -> target, inside im's __text."""
    va, a = words_of(kc, im)
    out = []
    for k, rd in adrp_index(kc, im).get(target & ~0xFFF, ()):
        for j in range(1, 5):
            if k + j >= len(a): break
            i = a[k + j]
            if is_add_imm64(i) and (i & 0x1F) == rd and ((i >> 5) & 0x1F) == rd:
                if (target & ~0xFFF) + add_imm(i) == target: out.append(va + 4 * (k + j))
                break
    return out


def func_bounds(kc, im, va):
    """[start, end) of the function containing va: start = nearest PACIBSP (with its BTI if any) at or before va,
    end = next PACIBSP after va (functions never contain a second PACIBSP)."""
    tva, toff, tsz = im.text()
    s = va & ~3
    while s >= tva and kc.insn(s) != PACIBSP: s -= 4
    if s < tva: raise SystemExit(f"no function start before 0x{va:x}")
    if s - 4 >= tva and kc.insn(s - 4) == BTI_C: s -= 4
    e = (va & ~3) + 4
    while e < tva + tsz and kc.insn(e) != PACIBSP: e += 4
    if kc.insn(e - 4) == BTI_C: e -= 4
    return s, e


def funcs_referencing(kc, im, target):
    return sorted({func_bounds(kc, im, x) for x in xrefs(kc, im, target)})


def rec(kc, rid, va, orig, new, summary, evidence):
    off = kc.off(va)
    if kc.d[off:off + len(orig)] != orig: raise SystemExit(f"{rid}: original bytes mismatch at 0x{va:x}")
    return {"id": rid, "offset": off, "originalBytes": orig.hex(), "replacementBytes": new.hex(),
            "summary": summary, "component": "kernelcache", "evidence": evidence, "va": f"0x{va:x}"}


def w(v): return struct.pack('<I', v)


# ------------------------------------------------------------------------------------------------ ramdisk set
def find_mount_union(kc):
    """__mac_mount: the only place in XNU with
         A: TBNZ Wf,#5,X              (flags & MNT_UNION)
            ... LDRB Wt,[Xm,#imm] ; TBNZ Wt,#6,Y   (covered vnode's mount has MNT_ROOTFS) within 0x60 of A
         C: TBZ  Wf,#5,A+4            (second path jumping back right behind A)"""
    im = kc.img('com.apple.kernel')
    va0, arr = words_of(kc, im)
    words = text_words(kc, im)
    hits = []
    for k, i in enumerate(arr):
        if not (i & 0x7E000000 == 0x36000000 and (i >> 24) & 1 and tb_bit(i) == 5 and (i >> 31) == 0): continue
        a = va0 + 4 * k
        rf = i & 0x1F
        cs = [c for c in range(a + 8, a + 0x400, 4) if c in words and is_tb(words[c]) and not tb_nz(words[c])
              and tb_bit(words[c]) == 5 and (words[c] & 0x1F) == rf and tb_target(words[c], c) == a + 4]
        rs = [r for r in range(a + 4, a + 0x60, 4) if r in words and r + 4 in words and is_ldrb_uimm(words[r])
              and is_tb(words[r + 4]) and tb_nz(words[r + 4]) and tb_bit(words[r + 4]) == 6
              and (words[r + 4] & 0x1F) == (words[r] & 0x1F)]
        if len(cs) == 1 and len(rs) == 1: hits.append((a, rs[0], cs[0]))
    if len(hits) != 1: raise SystemExit(f"mount union/rootfs: expected 1 site, found {[tuple(map(hex, h)) for h in hits]}")
    a, r, c = hits[0]
    rt = words[r] & 0x1F
    ev = [f"TBNZ W{words[a] & 0x1F},#5 @0x{a:x}", f"LDRB W{rt},[..,#0x{(words[r] >> 10) & 0xFFF:x}] ; TBNZ #6 @0x{r:x}",
          f"TBZ #5 -> 0x{a + 4:x} @0x{c:x}"]
    return [
        rec(kc, "kernel.mount.union-1", a, w(words[a]), w(NOP), "__mac_mount: allow MNT_UNION (tbnz wflags,#5 -> nop)", ev),
        rec(kc, "kernel.mount.rootfs", r, w(words[r]), w(0xAA1F03E0 | rt), "__mac_mount: ignore MNT_ROOTFS of covered vnode (ldrb -> mov xt,xzr)", ev),
        rec(kc, "kernel.mount.union-2", c, w(words[c]), w(0x14000000 | (((a + 4 - c) >> 2) & 0x3FFFFFF)),
            "__mac_mount: allow MNT_UNION on 2nd path (tbz -> b)", ev),
    ]


def find_rd_string(kc, image, companion, rid, nbytes, summary):
    """The "rd" boot-arg string of `image` whose referencing function also references `companion`."""
    im = kc.img(image)
    comp = set(im.cstrings(companion))
    if not comp: raise SystemExit(f"{rid}: companion string {companion!r} not found in {image}")
    hits = []
    for s in im.cstrings("rd"):
        for (fs, fe) in funcs_referencing(kc, im, s):
            if any(fs <= x < fe for c in comp for x in xrefs(kc, im, c)):
                hits.append((s, fs))
    strings = sorted({h[0] for h in hits})
    if len(strings) != 1: raise SystemExit(f"{rid}: expected one \"rd\" string next to {companion!r}, found {list(map(hex, strings))}")
    s = strings[0]
    orig = b"rd\0"[:nbytes]; new = b"jb\0"[:nbytes]
    return [rec(kc, rid, s, orig, new, summary, [f"\"rd\" @0x{s:x} used by fn 0x{h[1]:x} with {companion!r}" for h in hits])]


def ramdisk_set(kc):
    return (find_mount_union(kc)
            + find_rd_string(kc, 'com.apple.kernel', 'md0', 'kernel.rootdev.rename', 2,
                             "XNU boot-arg 'rd' -> 'jb' (bsd_init / IOFindBSDRoot share the string; kexts don't see rd=md0)")
            + find_rd_string(kc, 'com.apple.filesystems.apfs', 'rootdev', 'kernel.apfs.rd.rename', 3,
                             "APFS root-mount ramdisk check: boot-arg 'rd' -> 'jb', so APFS roots on md0 with jb=md0"))


# ------------------------------------------------------------------------------------------------ osb set
SEP_STUB_IDS = {  # known REQUIRE(!booted) panic stubs -> stable record ids (others: kernel.sep.<name>.no-panic)
    'DispatchHiloUpdateTimer': 'kernel.sep.hilo-update-timer.no-panic',
    'DispatchUserClientLynxGetCPSN': 'kernel.sep.lynx-get-cpsn.no-panic',
    'DispatchUserClientLynxGetPubKey': 'kernel.sep.lynx-get-pubkey.no-panic',
}


def find_sep_booted_stubs(kc):
    """AppleSEPUserClient dispatchers wait for a SEP endpoint and, when it never shows up but sep-booted is
    true, `CMP Xa,Xb (kOSBooleanTrue) ; B.EQ <BL REQUIRE(!booted) stub>`. On OS B SEP OS never comes up, so every
    such B.EQ becomes a NOP and the dispatcher returns its error code instead of panicking."""
    im = kc.img('com.apple.driver.AppleSEPManager')
    booted = im.cstrings("!booted")
    if not booted: raise SystemExit("sep stubs: no \"!booted\" string")
    names = {}
    for va in im.cstring_prefix("static IOReturn AppleSEPUserClient::"):
        o = kc.off(va); s = kc.d[o:o + 200].split(b'\0')[0].decode(errors='replace')
        names[va] = s.split("::", 1)[1].split("(", 1)[0]
    words = text_words(kc, im)
    out = []
    for b in booted:
        for x in xrefs(kc, im, b):
            st = x
            while st > x - 0x40 and words.get(st) != BTI_C: st -= 4
            if words.get(st) != BTI_C: raise SystemExit(f"sep stubs: no BTI before !booted xref 0x{x:x}")
            fname = [names[n] for n in names if any(st <= y < x + 4 for y in xrefs(kc, im, n))]
            if len(fname) != 1: raise SystemExit(f"sep stubs: stub 0x{st:x} names {fname}")
            bls = [p for p, i in words.items() if is_bl(i) and bl_target(i, p) == st]
            sites = [p for p, i in words.items() for bl in bls if is_bcond(i) and (i & 0xF) == 0 and bcond_target(i, p) == bl
                     and is_cmp_x_reg(words.get(p - 4, 0))]
            if len(sites) != 1: raise SystemExit(f"sep stubs: {fname[0]}: expected 1 guarded B.EQ, found {list(map(hex, sites))}")
            p = sites[0]
            rid = SEP_STUB_IDS.get(fname[0], f"kernel.sep.{fname[0]}.no-panic")
            out.append(rec(kc, rid, p, w(words[p]), w(NOP),
                           f"AppleSEPUserClient::{fname[0]}: no SEP endpoint but sep-booted -> return the error instead of REQUIRE(!booted) panic",
                           [f"stub 0x{st:x} (\"!booted\" @0x{b:x})", f"CMP ; B.EQ @0x{p:x} -> BL 0x{bcond_target(words[p], p):x}"]))
    missing = [n for n in SEP_STUB_IDS.values() if n not in {r['id'] for r in out}]
    if missing: print(f"  note: no stub for {missing} in this build", file=sys.stderr)
    return sorted(out, key=lambda r: r['offset'])


def find_aks_sep_booted(kc):
    """AppleSEPKeyStore's 'is SEP booted' helper is the only AKS function reading the "sep-booted" property.
    With it returning false AKS answers kIOReturnNotReady instead of waiting forever for the sks endpoint."""
    im = kc.img('com.apple.driver.AppleSEPKeyStore')
    s = im.cstrings("sep-booted")
    fns = sorted({f for x in s for f in funcs_referencing(kc, im, x)})
    if len(fns) != 1: raise SystemExit(f"aks: expected one sep-booted reader, found {[tuple(map(hex, f)) for f in fns]}")
    fs = fns[0][0]
    p = fs + 4 if kc.insn(fs) == BTI_C else fs
    i0, i1 = kc.insn(p), kc.insn(p + 4)
    if i0 != PACIBSP or (i1 & 0xFF8003FF) != 0xD10003FF:
        raise SystemExit(f"aks: unexpected prologue at 0x{p:x}: {i0:08x} {i1:08x}")
    ev = [f"only \"sep-booted\" reader in AppleSEPKeyStore: fn 0x{fs:x}"]
    return [rec(kc, "kernel.aks.sep-booted.false.0", p, w(i0), w(0x52800000), "AppleSEPKeyStore 'is SEP booted' -> false: PACIBSP -> MOV W0,#0 (BTI kept)", ev),
            rec(kc, "kernel.aks.sep-booted.false.1", p + 4, w(i1), w(RET), "SUB SP,SP,#imm -> RET (no frame/PAC set up yet)", ev)]


def find_sleep_sep_not_alive(kc):
    """AppleSEPManager::_setPowerState, sleep (new state 0): `CBZ W8,T ; LDR W8,[Xn] ; CMP W8,#2 ; B.NE full`
    with T right after the B.NE. Only an alive SEP (state >= 7) should get the endpoint handshake (it waits for
    hilo/xART endpoints, panics when absent and then waits unbounded for SEP_ASLEEP)."""
    im = kc.img('com.apple.driver.AppleSEPManager')
    fn_str = im.cstring_prefix("IOReturn AppleSEPManager::_setPowerState(")
    fns = sorted({f for s in fn_str for f in funcs_referencing(kc, im, s)})
    hits = []
    for fs, fe in fns:
        for p in range(fs, fe - 12, 4):
            i0, i1, i2, i3 = (kc.insn(p + 4 * k) for k in range(4))
            if (is_cbz_w(i0) and (i0 & 0x1F) == 8 and cb_target(i0, p) == p + 16 and is_ldr_w_uimm(i1) and (i1 & 0x1F) == 8
                    and is_cmp_w_imm(i2) and ((i2 >> 5) & 0x1F) == 8 and ((i2 >> 10) & 0xFFF) == 2
                    and is_bcond(i3) and (i3 & 0xF) == 1):
                hits.append((fs, p))
    if len(hits) != 1: raise SystemExit(f"sleep: expected 1 site, found {[tuple(map(hex, h)) for h in hits]}")
    fs, p = hits[0]
    cmp_va, b_va = p + 8, p + 12
    ci, bi = kc.insn(cmp_va), kc.insn(b_va)
    new_cmp = (ci & ~(0xFFF << 10)) | (7 << 10)
    new_b = (bi & ~0xF) | 0xA
    ev = [f"_setPowerState fn 0x{fs:x}", f"CBZ W8 ; LDR W8 ; CMP W8,#2 ; B.NE @0x{p:x}"]
    return [rec(kc, "kernel.sep.sleep.sep-not-alive.0", cmp_va, w(ci), w(new_cmp),
                "AppleSEPManager::_setPowerState sleep: CMP W8(_sep_state),#2 -> #7 (SEP OS never alive on OS B)", ev),
            rec(kc, "kernel.sep.sleep.sep-not-alive.1", b_va, w(bi), w(new_b),
                "B.NE -> B.GE: only an alive SEP (7/8/9) gets the endpoint sleep handshake; 1..6 sleep the IOP like 0/2", ev)]


def osb_set(kc):
    return find_sep_booted_stubs(kc) + find_aks_sep_booted(kc) + find_sleep_sep_not_alive(kc)


SETS = {'ramdisk': ramdisk_set, 'osb': osb_set}


def load_kernel(path):
    data = open(path, 'rb').read()
    if data[:4] != b'\xcf\xfa\xed\xfe':
        from pyimg4 import IM4P
        p = IM4P(data)
        try: p.payload.decompress()
        except Exception: pass
        data = p.payload.output().data
    return Kernelcache(bytes(data))


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('kernel'); ap.add_argument('set', choices=sorted(SETS)); ap.add_argument('-o', '--out')
    a = ap.parse_args()
    recs = SETS[a.set](load_kernel(a.kernel))
    txt = json.dumps(recs, indent=1) + "\n"
    if a.out: open(a.out, 'w').write(txt)
    else: sys.stdout.write(txt)
    for r in recs: print(f"  {r['id']:38s} {r['va']}  {r['originalBytes']} -> {r['replacementBytes']}", file=sys.stderr)


if __name__ == '__main__':
    main()
