/*
 * jbinit — fake dyld (static MH_DYLINKER installed as /usr/lib/dyld on the jb ramdisk).
 * The kernel execs the ramdisk's /sbin/launchd, which names /usr/lib/dyld as its dylinker,
 * so this code runs as PID 1 before anything else in userland.
 */
    .text
    .globl __dyld_start
    .p2align 2
__dyld_start:
    mov     x0, sp                  // -> mach_header*, argc, argv..., envp..., apple...
    and     x1, x0, #~0xf
    mov     sp, x1
    bl      _jbinit_main
    mov     x16, #1                 // exit (never reached: main execs launchd or spins)
    svc     #0x80
1:  b       1b

/* long sc(long num, long a0, long a1, long a2, long a3, long a4, long a5)
 * returns result, or -errno on failure (carry set). */
    .globl _sc
    .p2align 2
_sc:
    mov     x16, x0
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    mov     x4, x5
    mov     x5, x6
    svc     #0x80
    b.cc    2f
    neg     x0, x0
2:  ret

/* long sc_fork(void): 0 in the child, child pid in the parent, -errno on failure
 * (XNU returns x1 = 1 in the child, 0 in the parent) */
    .globl _sc_fork
    .p2align 2
_sc_fork:
    mov     x16, #2
    svc     #0x80
    b.cs    4f
    cbz     x1, 3f
    mov     x0, #0
3:  ret
4:  neg     x0, x0
    ret
