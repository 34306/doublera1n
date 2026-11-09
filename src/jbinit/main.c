/*
 * jbinit — PID 1 on the jailbreak ramdisk (no libc; raw syscalls).
 *
 *  1. log to /dev/console (visible with -v)
 *  2. wait for the stock System volume and mount it READ-ONLY over "/" (MNT_UNION, live fs of the
 *     sealed volume — nothing on disk is modified)
 *  3. remount devfs on the new /dev
 *  4. fork: the child waits until launchd has mounted DataB on /private/var (and grafted the OS cryptex,
 *     i.e. the dyld shared cache exists), then execs /jbin/jbloader (ramdisk-only top-level dir, visible
 *     through the union) which installs/starts the /var/jb userland
 *  5. the parent execve's the REAL /sbin/launchd (resolved from the stock System volume)
 *
 * If anything fails it prints the error and keeps retrying / spinning so it can be read on screen.
 */
typedef unsigned long size_t;
typedef unsigned long uint64_t;
typedef unsigned int uint32_t;
typedef int int32_t;

long sc(long n, long a0, long a1, long a2, long a3, long a4, long a5);
long sc_fork(void);

#define SYS_read    3
#define SYS_write   4
#define SYS_open    5
#define SYS_close   6
#define SYS_fchdir  13
#define SYS_chdir   12
#define SYS_execve  59
#define SYS_select  93
#define SYS_mkdir   136
#define SYS_mount   167
#define SYS_stat64  338

#ifdef OS2
#define SYSVOL_LOG "OS2System"
#define SYSVOL_WAIT_LOG "OS2System"
#else
#define SYSVOL_LOG "disk1s1"
#define SYSVOL_WAIT_LOG "/dev/disk1s1"
#endif

#define O_RDWR      2
#define O_RDONLY    0
#define MNT_RDONLY  0x00000001
#define MNT_UNION   0x00000020

enum { APFS_MOUNT_AS_ROOT = 0, APFS_MOUNT_FILESYSTEM = 1 };

struct apfs_mount_args {
    char *fspec;
    uint64_t apfs_flags;
    uint32_t mount_mode;
    uint32_t pad1;
    uint32_t unk_flags;
    char snapshot[256];
    void *im4p_ptr;
    uint32_t im4p_size;
    uint32_t pad2;
    void *im4m_ptr;
    uint32_t im4m_size;
    uint32_t im_4cc;
    uint32_t cryptex_type;
    int32_t auth_mode;
    uint32_t uid;
    uint32_t gid;
} __attribute__((packed, aligned(4)));

static long con = -1;

static size_t slen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
static void out(const char *s) { if (con >= 0) sc(SYS_write, con, (long)s, slen(s), 0, 0, 0); }
static void outhex(long v) {
    char b[20]; int i = 19; b[i] = 0;
    unsigned long u = (unsigned long)v;
    if (v < 0) { out("-"); u = (unsigned long)(-v); }
    do { b[--i] = "0123456789abcdef"[u & 15]; u >>= 4; } while (u && i > 2);
    b[--i] = 'x'; b[--i] = '0';
    out(&b[i]);
}
static void say(const char *what, long r) { out("[jbinit] "); out(what); out(" -> "); outhex(r); out("\n"); }
static void sleep_s(long s) { struct { long sec; int usec; int pad; } tv = { s, 0, 0 }; sc(SYS_select, 0, 0, 0, 0, (long)&tv, 0); }
static void zero(void *p, size_t n) { char *c = p; while (n--) *c++ = 0; }

static char statbuf[512];

static void wait_for(const char *p) {
    for (int i = 0; sc(SYS_stat64, (long)p, (long)statbuf, 0, 0, 0, 0) != 0; i++) {
        if (i % 30 == 0) { out("[jbinit] child waiting for "); out(p); out("\n"); }
        sleep_s(1);
    }
}

void jbinit_main(long *sp) {
    long r;
    for (int i = 0; i < 50 && con < 0; i++) {
        con = sc(SYS_open, (long)"/dev/console", O_RDWR, 0, 0, 0, 0);
        if (con < 0) sleep_s(1);
    }
    out("\n\n[jbinit] ===== jbinit =====\n");

    /* the union mount only merges "/" itself for path lookups made later -> keep a handle on the ramdisk's
       /jbin now; the loader child fchdir()s into it and execs jbloader by a relative path */
    long jbin = sc(SYS_open, (long)"/jbin", O_RDONLY, 0, 0, 0, 0);
    say("open ramdisk /jbin", jbin);

    /* 2. stock System volume -> "/" (read-only, union over the ramdisk) */
#ifdef OS2
    /* 2nd iOS (built with -DOS2 -> payload/boot/dyld-os2): its own System volume OS2System, named by
       /jbin/os2-system ("diskNsM", written by mk_osbjb.py from what os2vol reported). No fallback to the stock
       System volume: that is a different iOS build. */
    static char sysbuf[64] = "/dev/";
    {
        long fd = sc(SYS_open, (long)"/jbin/os2-system", O_RDONLY, 0, 0, 0, 0);
        long n = fd >= 0 ? sc(SYS_read, fd, (long)(sysbuf + 5), sizeof(sysbuf) - 6, 0, 0, 0) : -1;
        if (fd >= 0) sc(SYS_close, fd, 0, 0, 0, 0, 0);
        if (n <= 0) { say("read /jbin/os2-system FAILED", n); for (;;) sleep_s(60); }
        for (long i = 5; i < 5 + n; i++) if (sysbuf[i] == '\n' || sysbuf[i] == ' ') { sysbuf[i] = 0; break; }
        sysbuf[5 + n] = 0;
        out("[jbinit] 2nd iOS System volume: "); out(sysbuf); out("\n");
    }
    const char *sysdev = sysbuf;
#else
    const char *sysdev = "/dev/disk1s1";
#endif
    for (int i = 0; ; i++) {
        r = sc(SYS_stat64, (long)sysdev, (long)statbuf, 0, 0, 0, 0);
        if (r == 0) break;
        if (i % 5 == 0) say("waiting for " SYSVOL_WAIT_LOG, r);
        sleep_s(1);
    }
    struct apfs_mount_args a;
    zero(&a, sizeof(a));
    a.fspec = (char *)sysdev;
    a.apfs_flags = MNT_RDONLY | MNT_UNION;
    a.mount_mode = APFS_MOUNT_FILESYSTEM;
    for (int i = 0; ; i++) {
        /* even attempts: live fs of the sealed System volume; odd: its default (root) snapshot */
        a.mount_mode = (i & 1) ? APFS_MOUNT_AS_ROOT : APFS_MOUNT_FILESYSTEM;
        r = sc(SYS_mount, (long)"apfs", (long)"/", MNT_RDONLY | MNT_UNION, (long)&a, 0, 0);
        say((i & 1) ? "mount apfs " SYSVOL_LOG " (root snapshot) on / ro,union" : "mount apfs " SYSVOL_LOG " (livefs) on / ro,union", r);
        if (r == 0) break;
        sleep_s(2);
        if (i > 30) { out("[jbinit] giving up\n"); for (;;) sleep_s(60); }
    }
    r = sc(SYS_stat64, (long)"/System/Library/CoreServices/SystemVersion.plist", (long)statbuf, 0, 0, 0, 0);
    say("stat SystemVersion.plist", r);
#ifdef OS2
    /* the staging step (dualboot.py os2 install) leaves /.dualboot-os2 on OS2System: anything else mounted here
       would be the wrong volume -> stop before launchd runs from it */
    r = sc(SYS_stat64, (long)"/.dualboot-os2", (long)statbuf, 0, 0, 0, 0);
    say("stat /.dualboot-os2 (2nd iOS marker)", r);
    if (r != 0) { out("[jbinit] not the 2nd iOS System volume - stopping\n"); for (;;) sleep_s(60); }
#endif

    /* 3. devfs on the new /dev */
    r = sc(SYS_mount, (long)"devfs", (long)"/dev", 0, (long)"devfs", 0, 0);
    say("mount devfs /dev", r);

    /* 3b. ramdisk /jbin -> /cores via bindfs (source "." = the /jbin handle), so launchd can load
           /cores/obhook.dylib (the launchd hook) before Preboot/DataB exist */
    long hooked = -1;
    if (jbin >= 0 && sc(SYS_fchdir, jbin, 0, 0, 0, 0, 0) == 0) {
        r = sc(SYS_mount, (long)"bindfs", (long)"/cores", MNT_RDONLY, (long)".", 0, 0);
        say("bindfs ramdisk /jbin -> /cores", r);
        if (r == 0) hooked = sc(SYS_stat64, (long)"/cores/obhook.dylib", (long)statbuf, 0, 0, 0, 0);
        say("stat /cores/obhook.dylib", hooked);
        /* 3c. launchd job cache override: /jbin/xpc = stock /System/Library/xpc with our job edits (securityd ->
               copy with obkeychain, watchdogd crash-loop keys removed; built by mk_osbjb.py). launchd_cache_loader
               reads the fixed path /System/Library/xpc/launchd.plist and, with launchd_unsecure_cache= in the boot-args,
               skips its signature/trust-cache check. Nothing is written to disk; if this fails launchd simply uses the
               stock cache. */
        if (sc(SYS_stat64, (long)"xpc/launchd.plist", (long)statbuf, 0, 0, 0, 0) == 0) {
            r = sc(SYS_mount, (long)"bindfs", (long)"/System/Library/xpc", MNT_RDONLY, (long)"xpc", 0, 0);
            say("bindfs ramdisk /jbin/xpc -> /System/Library/xpc", r);
        }
        sc(SYS_chdir, (long)"/", 0, 0, 0, 0, 0);
    }

    /* 4. loader child */
    r = sc_fork();
    if (r == 0) {
        /* no pointer tables (nothing rebases a static dylinker): one call per path */
        wait_for("/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld");   /* OS cryptex grafted */
        wait_for("/private/var/dualboot-setup.log");                           /* DataB on /private/var */
        sleep_s(3);
        char *volatile cargv[2]; char *volatile cenvp[2];
        cargv[0] = (char *)"/jbin/jbloader"; cargv[1] = 0;
        cenvp[0] = (char *)"PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/usr/bin:/bin:/usr/sbin:/sbin"; cenvp[1] = 0;
        r = sc(SYS_fchdir, jbin, 0, 0, 0, 0, 0);
        say("child: fchdir ramdisk /jbin", r);
        out("[jbinit] child: exec ./jbloader (ramdisk /jbin)\n");
        r = sc(SYS_execve, (long)"./jbloader", (long)(char **)cargv, (long)(char **)cenvp, 0, 0, 0);
        say("child execve jbloader FAILED", r);
        for (;;) sleep_s(3600);
    }
    say("fork loader child (pid)", r);
    if (jbin >= 0) sc(SYS_close, jbin, 0, 0, 0, 0, 0);   /* launchd must not inherit it */

    /* 5. hand over to the real launchd */
    /* built at runtime: a static dylinker has nobody to apply rebases, so no pointer tables in data */
    char *volatile argv[2]; char *volatile envp[2];
    argv[0] = (char *)"/sbin/launchd"; argv[1] = 0;
    envp[0] = hooked == 0 ? (char *)"DYLD_INSERT_LIBRARIES=/cores/obhook.dylib" : (char *)"JB_BOOTED=1"; envp[1] = 0;
    out(hooked == 0 ? "[jbinit] launchd will load /cores/obhook.dylib\n" : "[jbinit] launchd without obhook\n");
    out("[jbinit] exec real /sbin/launchd\n");
    r = sc(SYS_execve, (long)"/sbin/launchd", (long)(char **)argv, (long)(char **)envp, 0, 0, 0);
    say("execve launchd FAILED", r);
    for (;;) sleep_s(60);
}
