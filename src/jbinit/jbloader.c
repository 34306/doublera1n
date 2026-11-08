/*
 * jbloader — started once per boot by jbinit's child after launchd mounted DataB on /private/var.
 *   1. first boot: unpack /jbin/bootstrap.tar.gz (Procursus rootless, ./var/jb/...) onto / (=> DataB:/jb)
 *   2. root's authorized_keys from /jbin/authorized_keys, ssh host keys (ssh-keygen -A)
 *   3. start OpenSSH sshd on port 22 (reach it with `iproxy 2222 22`)
 * Everything is logged to /dev/console (UART) and /var/jb/var/log/jbloader.log.
 * Only /private/var (= DataB) is written.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <mach/mach.h>

/* not in the iOS SDK headers */
kern_return_t task_for_pid(mach_port_t target_tport, int pid, mach_port_t *t);
int proc_listallpids(void *buffer, int buffersize);
int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
/* iOS SDK ships libarchive.tbd but no headers: the (stable) libarchive 3 API subset used here */
struct archive; struct archive_entry;
typedef long long la_int64_t;
#define ARCHIVE_EOF 1
#define ARCHIVE_OK 0
#define ARCHIVE_WARN (-20)
#define ARCHIVE_EXTRACT_OWNER (0x0001)
#define ARCHIVE_EXTRACT_PERM (0x0002)
#define ARCHIVE_EXTRACT_TIME (0x0004)
#define ARCHIVE_EXTRACT_ACL (0x0020)
#define ARCHIVE_EXTRACT_FFLAGS (0x0040)
#define ARCHIVE_EXTRACT_XATTR (0x0080)
struct archive *archive_read_new(void);
struct archive *archive_write_disk_new(void);
int archive_read_support_format_tar(struct archive *);
int archive_read_support_filter_gzip(struct archive *);
int archive_write_disk_set_options(struct archive *, int);
int archive_read_open_filename(struct archive *, const char *, size_t);
int archive_read_next_header(struct archive *, struct archive_entry **);
int archive_read_data_block(struct archive *, const void **, size_t *, la_int64_t *);
int archive_write_header(struct archive *, struct archive_entry *);
int archive_write_data_block(struct archive *, const void *, size_t, la_int64_t);
int archive_write_finish_entry(struct archive *);
int archive_read_free(struct archive *);
int archive_write_free(struct archive *);
const char *archive_error_string(struct archive *);
const char *archive_entry_pathname(struct archive_entry *);
la_int64_t archive_entry_size(struct archive_entry *);

extern char **environ;
static FILE *logf;

static void say(const char *fmt, ...) {
    char line[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(line, sizeof line, fmt, ap); va_end(ap);
    int c = open("/dev/console", O_WRONLY | O_NOCTTY);
    if (c >= 0) { dprintf(c, "[jbloader] %s\n", line); close(c); }
    if (logf) { fprintf(logf, "%s\n", line); fflush(logf); }
}

static int run(const char *const argv[], int wait) {
    pid_t pid; posix_spawn_file_actions_t fa; posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/console", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/console", O_WRONLY, 0);
    int r = posix_spawn(&pid, argv[0], &fa, NULL, (char *const *)argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (r) { say("spawn %s failed: %d (%s)", argv[0], r, strerror(r)); return -1; }
    say("spawned %s pid %d", argv[0], pid);
    if (!wait) return 0;
    int st = 0; while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
    say("  %s -> %d", argv[0], rc);
    return rc;
}

static int copy_data(struct archive *ar, struct archive *aw) {
    const void *buff; size_t size; la_int64_t offset;
    for (;;) {
        int r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF) return ARCHIVE_OK;
        if (r < ARCHIVE_OK) return r;
        if (archive_write_data_block(aw, buff, size, offset) < ARCHIVE_OK) return ARCHIVE_WARN;
    }
}

static int unpack(const char *tarball) {
    struct archive *a = archive_read_new(), *ext = archive_write_disk_new();
    archive_read_support_format_tar(a); archive_read_support_filter_gzip(a);
    archive_write_disk_set_options(ext, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_OWNER |
                                        ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_XATTR);
    if (archive_read_open_filename(a, tarball, 1 << 16)) { say("open %s: %s", tarball, archive_error_string(a)); return -1; }
    long n = 0, bad = 0; struct archive_entry *e; int r;
    /* entries are ./var/jb/...: extract relative to /private so nothing touches "/" or the /var symlink
       on the read-only System volume (hardlink targets ./var/jb/... resolve the same way) */
    const char *base = getenv("JBL_TEST_ROOT") ? getenv("JBL_TEST_ROOT") : "/private";
    if (chdir(base)) { say("chdir %s: %s", base, strerror(errno)); return -1; }
    while ((r = archive_read_next_header(a, &e)) != ARCHIVE_EOF) {
        if (r < ARCHIVE_WARN) { say("header: %s", archive_error_string(a)); bad++; break; }
        const char *p = archive_entry_pathname(e);
        if (!strcmp(p, "./") || !strcmp(p, "./var/") || !strcmp(p, "var/")) continue;
        if (strncmp(p, "./var/jb", 8) && strncmp(p, "var/jb", 6)) {
            say("skip unexpected entry %s", p); continue;        /* never write outside /var/jb */
        }
        if (archive_write_header(ext, e) < ARCHIVE_OK) { bad++; if (bad < 10) say("write %s: %s", p, archive_error_string(ext)); }
        else if (archive_entry_size(e) > 0 && copy_data(a, ext) < ARCHIVE_OK) { bad++; if (bad < 10) say("data %s: %s", p, archive_error_string(ext)); }
        archive_write_finish_entry(ext);
        n++;
    }
    archive_read_free(a); archive_write_free(ext);
    say("unpacked %ld entries, %ld errors", n, bad);
    return bad ? -1 : 0;
}

static int exists(const char *p) { struct stat sb; return stat(p, &sb) == 0; }

static void copy_file(const char *from, const char *to, mode_t mode) {
    int i = open(from, O_RDONLY); if (i < 0) { say("open %s: %s", from, strerror(errno)); return; }
    int o = open(to, O_WRONLY | O_CREAT | O_TRUNC, mode); if (o < 0) { say("create %s: %s", to, strerror(errno)); close(i); return; }
    char b[8192]; ssize_t n; while ((n = read(i, b, sizeof b)) > 0) write(o, b, n);
    close(i); close(o); chmod(to, mode);
}

/* jbloader was forked by jbinit before launchd existed, so it (and sshd, and every SSH session) has no
   bootstrap port: XPC to launchd/logd fails ("Broken pipe"). Borrow the system bootstrap port from a
   daemon launchd spawned (needs task_for_pid: platform via the boot TC + task_for_pid-allow entitlement,
   TXM boot-permissive relaxes the task-port policy). */
static int find_pid(const char *path) {
    static int pids[4096]; int n = proc_listallpids(pids, sizeof pids);
    char buf[1024];
    for (int i = 0; i < n; i++) if (proc_pidpath(pids[i], buf, sizeof buf) > 0 && !strcmp(buf, path)) return pids[i];
    return -1;
}

static int adopt_launchd_bootstrap(void) {
    static const char *donors[] = { "/usr/libexec/lockdownd", "/usr/sbin/wifid", "/usr/libexec/securityd",
                                    "/usr/libexec/backboardd", NULL };
    for (int round = 0; round < 60; round++) {
        for (int i = 0; donors[i]; i++) {
            int pid = find_pid(donors[i]); if (pid <= 0) continue;
            mach_port_t t = MACH_PORT_NULL, bp = MACH_PORT_NULL;
            kern_return_t kr = task_for_pid(mach_task_self(), pid, &t);
            if (kr != KERN_SUCCESS) { if (round == 0) say("task_for_pid(%s=%d) -> %d", donors[i], pid, kr); continue; }
            kr = task_get_special_port(t, TASK_BOOTSTRAP_PORT, &bp);
            mach_port_deallocate(mach_task_self(), t);
            if (kr != KERN_SUCCESS || !MACH_PORT_VALID(bp)) { say("bootstrap port of %s: kr %d port %x", donors[i], kr, bp); continue; }
            kr = task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, bp);
            bootstrap_port = bp;
            say("adopted launchd bootstrap port 0x%x from %s (pid %d), set -> %d", bp, donors[i], pid, kr);
            return 0;
        }
        sleep(2);
    }
    say("could not adopt a bootstrap port - launchctl will not work from SSH");
    return -1;
}

/* Fallback when osb-boot.sh is absent: run a patched mobileactivationd (patches: should_hactivate=1,
   state report always "Activated", migration gate removed) instead of the sealed /usr/libexec one by replacing
   the launchd job user/501/com.apple.mobileactivationd with a copy of its cache entry whose program is the patched
   binary (`launchctl debug --program` returns ENOTSUP), then unbrick (-> dealwith_activation hactivation path). */
static void ma_replace(void) {
    const char *L = "/var/jb/usr/bin/launchctl", *P = "/var/jb/Library/LaunchDaemons/com.apple.mobileactivationd.plist";
    if (!exists("/private/var/jb/usr/libexec/mobileactivationd") || !exists("/private" "/var/jb/Library/LaunchDaemons/com.apple.mobileactivationd.plist")) {
        say("ma_replace: patched daemon or plist missing"); return; }
    const char *bo[] = { L, "bootout", "user/501/com.apple.mobileactivationd", NULL };
    const char *bs[] = { L, "bootstrap", "user/501", P, NULL };
    const char *ma[] = { "/var/jb/usr/bin/maactivate", NULL };
    for (int i = 0; i < 10; i++) {
        int a = run(bo, 1), b = run(bs, 1);
        say("ma_replace: bootout %d bootstrap %d", a, b);
        if (b == 0) break;
        sleep(3);
    }
    run(ma, 1);
}

int main(void) {
    /* cwd = the ramdisk's /jbin (jbinit fchdir'd there; not reachable by absolute path through the union) */
    int rd = open(".", O_RDONLY);
    say("===== jbloader (OS B) pid %d uid %d, ramdisk dir fd %d =====", getpid(), getuid(), rd);
    if (!exists("/private/var/jb/.bootstrapped")) {
        say("first boot: unpacking bootstrap.tar.gz -> /var/jb");
        fchdir(rd);
        if (unpack("bootstrap.tar.gz") == 0) {
            int f = open("/private/var/jb/.bootstrapped", O_WRONLY | O_CREAT, 0644); if (f >= 0) close(f);
        } else say("bootstrap unpack had errors (will retry next boot)");
    } else say("/var/jb already bootstrapped");
    mkdir("/private/var/jb/var", 0755); mkdir("/private/var/jb/var/log", 0755);
    logf = fopen("/private/var/jb/var/log/jbloader.log", "a");
    setenv("PATH", "/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin", 1);
    setenv("HOME", "/var/root", 1);

    /* activation helper (arm64e, cdhash in the boot trust cache): injected into mobileactivationd later */
    mkdir("/private/var/jb/usr/lib", 0755);
    fchdir(rd);
    if (exists("hacthook.dylib")) { copy_file("hacthook.dylib", "/private/var/jb/usr/lib/hacthook.dylib", 0755); say("installed /var/jb/usr/lib/hacthook.dylib"); }
    /* patched mobileactivationd, plus platform tools whose cdhashes are in the boot trust cache: launchctl (built
       with a weak _launch_active_user_switch import) and the debug helpers */
    mkdir("/private/var/jb/usr/libexec", 0755);
    if (exists("mobileactivationd")) { copy_file("mobileactivationd", "/private/var/jb/usr/libexec/mobileactivationd", 0755); say("installed patched /var/jb/usr/libexec/mobileactivationd"); }
    static const char *tools[] = { "launchctl", "bpexec", "lsimg", "hactpoke", "maactivate", NULL };
    for (int i = 0; tools[i]; i++) if (exists(tools[i])) {
        char to[256]; snprintf(to, sizeof to, "/private/var/jb/usr/bin/%s", tools[i]);
        copy_file(tools[i], to, 0755); say("installed %s", to);
    }

    /* root's home is /var/jb/var/root in the bootstrap's passwd (libiosexec reads /var/jb/etc/pwd.db),
       /var/root in the system one: install the key in both */
    mkdir("/private/var/root", 0755); mkdir("/private/var/root/.ssh", 0700);
    mkdir("/private/var/jb/var/root", 0755); mkdir("/private/var/jb/var/root/.ssh", 0700);
    if (exists("authorized_keys")) {
        copy_file("authorized_keys", "/private/var/root/.ssh/authorized_keys", 0600);
        copy_file("authorized_keys", "/private/var/jb/var/root/.ssh/authorized_keys", 0600);
        say("installed root authorized_keys");
    }
    chdir("/");

    /* Procursus first-run script (pwd_mkdb, dash/zsh/apt postinsts, openssh-server host keys); deletes itself */
    if (exists("/private/var/jb/prep_bootstrap.sh")) {
        setenv("NO_PASSWORD_PROMPT", "1", 1);
        const char *prep[] = { "/var/jb/usr/bin/dash", "/var/jb/prep_bootstrap.sh", NULL };
        say("running prep_bootstrap.sh");
        run(prep, 1);
        unsetenv("NO_PASSWORD_PROMPT");
    }

    if (!exists("/var/jb/etc/ssh/ssh_host_ed25519_key")) {
        const char *kg[] = { "/var/jb/usr/bin/ssh-keygen", "-A", NULL };
        run(kg, 1);
    }
    adopt_launchd_bootstrap();
    mkdir("/private/var/jb/Library", 0755); mkdir("/private/var/jb/Library/LaunchDaemons", 0755);
    fchdir(rd);
    if (exists("com.apple.mobileactivationd.plist"))
        copy_file("com.apple.mobileactivationd.plist", "/private/var/jb/Library/LaunchDaemons/com.apple.mobileactivationd.plist", 0644);
    chdir("/");
    /* per-boot fixups live on DataB and can be edited without rebuilding the ramdisk */
    if (exists("/private/var/jb/usr/libexec/osb-boot.sh")) {
        const char *ob[] = { "/var/jb/usr/bin/zsh", "/var/jb/usr/libexec/osb-boot.sh", NULL };
        say("running /var/jb/usr/libexec/osb-boot.sh (log /var/jb/var/log/osb-boot.log)");
        run(ob, 1);
    } else ma_replace();
    mkdir("/private/var/jb/var/empty", 0755); mkdir("/private/var/jb/var/run", 0755);
    const char *sshd[] = { "/var/jb/usr/sbin/sshd", "-D", "-e", "-p", "22",
                           "-o", "PermitRootLogin=prohibit-password", "-o", "PasswordAuthentication=no",
                           "-o", "PidFile=/var/jb/var/run/sshd.pid", NULL };
    for (int attempt = 0; attempt < 1000; attempt++) {
        int rc = run(sshd, 1);
        say("sshd exited (%d) - restarting in 5 s", rc);
        sleep(5);
    }
    return 0;
}
