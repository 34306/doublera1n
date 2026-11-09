/*
 * os2vol - volumes of the "2nd iOS" dual boot (DEVELOPING FEATURE). Runs on 2nd Data as root (over SSH).
 *
 *   os2vol list     every APFS volume: BSD name, name, role
 *   os2vol create   add OS2System (APFS role VM = 8) and OS2Data (role Enterprise = 512) to the System container
 *                   (/sbin/newfs_apfs -A, unencrypted); existing ones are reused. Prints
 *                   "OS2SYS <bsd>" and "OS2DATA <bsd>".
 *   os2vol delete   delete OS2System and OS2Data (APFSVolumeDelete) after strict checks
 *
 * Why these roles: the kernel's DT_get_fstab_entries mounts, for every /filesystems/fstab entry, the FIRST volume
 * of the boot container whose role equals the entry's vol.fs_role, and /sbin/mount refuses to boot when two
 * volumes have the Data role (0x40). Stock iOS 27 looks up 0x1/0x10/0x40/0x80/0xc0/0x100/0x140 (fstab),
 * 0x40 (/sbin/mount), 0x20 -> /private/var/logs, 0x280 -> /AppleInternal/Diags, 0x2c0 (apfs_boot_util), and the
 * phone already has a stock "User" volume with role 2. 2nd Data looks up role 0 (DataB). VM (8) and
 * Enterprise (512, a data-volume role) are looked up by nobody but the 2nd iOS DeviceTree (system-vol -> 8,
 * data-vol -> 512); create refuses if any other volume already has one of these roles.
 * Nothing but volumes named OS2System / OS2Data with exactly these roles is ever created or deleted.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <CoreFoundation/CoreFoundation.h>

typedef unsigned int io_object_t, io_iterator_t;
extern const unsigned int kIOMainPortDefault;
CFMutableDictionaryRef IOServiceMatching(const char *name);
int IOServiceGetMatchingServices(unsigned int port, CFDictionaryRef matching, io_iterator_t *it);
io_object_t IOIteratorNext(io_iterator_t it);
CFTypeRef IORegistryEntryCreateCFProperty(io_object_t e, CFStringRef key, CFAllocatorRef a, unsigned int opts);
int IORegistryEntryGetName(io_object_t e, char name[128]);
int IOObjectRelease(io_object_t o);
extern char **environ;

#define SYSNAME "OS2System"
#define DATANAME "OS2Data"
#define SYSROLE 8      /* APFS_VOL_ROLE_VM   (newfs_apfs -R v) */
#define DATAROLE 512   /* APFS_VOL_ROLE_ENTERPRISE (newfs_apfs -R n) */

struct vol { char bsd[64], name[128]; long role; };
static struct vol vols[64];
static int nvols;

static void cfstr(CFTypeRef v, char *out, size_t n) {
    out[0] = 0;
    if (!v) return;
    if (CFGetTypeID(v) == CFStringGetTypeID()) CFStringGetCString(v, out, n, kCFStringEncodingUTF8);
    else if (CFGetTypeID(v) == CFNumberGetTypeID()) { long long x = 0; CFNumberGetValue(v, kCFNumberLongLongType, &x); snprintf(out, n, "%lld", x); }
}

static int list_volumes(int print) {
    io_iterator_t it = 0; io_object_t e;
    nvols = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching("AppleAPFSVolume"), &it)) return -1;
    while ((e = IOIteratorNext(it)) && nvols < 64) {
        struct vol *v = &vols[nvols]; char full[128], rolev[32], reg[128] = "";
        CFTypeRef p;
        p = IORegistryEntryCreateCFProperty(e, CFSTR("BSD Name"), NULL, 0); cfstr(p, v->bsd, sizeof v->bsd); if (p) CFRelease(p);
        p = IORegistryEntryCreateCFProperty(e, CFSTR("FullName"), NULL, 0); cfstr(p, full, sizeof full); if (p) CFRelease(p);
        p = IORegistryEntryCreateCFProperty(e, CFSTR("RoleValue"), NULL, 0); cfstr(p, rolev, sizeof rolev); if (p) CFRelease(p);
        IORegistryEntryGetName(e, reg);
        strlcpy(v->name, full[0] ? full : reg, sizeof v->name);
        v->role = rolev[0] ? strtol(rolev, NULL, 0) : 0;
        if (print) printf("VOL %-12s role=%-5ld %s\n", v->bsd, v->role, v->name);
        nvols++;
        IOObjectRelease(e);
    }
    IOObjectRelease(it);
    return nvols;
}

static struct vol *named(const char *n, int *count) {
    struct vol *f = NULL; *count = 0;
    for (int i = 0; i < nvols; i++) if (!strcmp(vols[i].name, n)) { (*count)++; f = &vols[i]; }
    return f;
}

/* container BSD name ("disk1") of the single System-role volume; NULL if not exactly one */
static const char *system_container(void) {
    static char cont[64]; int n = 0;
    for (int i = 0; i < nvols; i++)
        if (vols[i].role == 1) { n++; strlcpy(cont, vols[i].bsd, sizeof cont); }
    if (n != 1) { fprintf(stderr, "expected exactly one System-role volume, found %d - refusing\n", n); return NULL; }
    char *s = strrchr(cont, 's'); if (s && s != cont) *s = 0;
    return cont;
}

static int in_container(const struct vol *v, const char *cont) {
    size_t L = strlen(cont);
    return !strncmp(v->bsd, cont, L) && v->bsd[L] == 's';
}

static int is_mounted(const char *bsd) {
    struct statfs *m; int n = getmntinfo(&m, MNT_NOWAIT); char dev[80];
    snprintf(dev, sizeof dev, "/dev/%s", bsd);
    for (int i = 0; i < n; i++) if (!strcmp(m[i].f_mntfromname, dev)) return 1;
    return 0;
}

static int run(const char *const argv[]) {
    pid_t pid; int st = 0;
    printf("run:"); for (int i = 0; argv[i]; i++) printf(" %s", argv[i]); printf("\n"); fflush(stdout);
    if (posix_spawn(&pid, argv[0], NULL, NULL, (char *const *)argv, environ)) { perror("posix_spawn"); return -1; }
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static int create_one(const char *name, const char *roleletter, long role, const char *cont) {
    int n; struct vol *v = named(name, &n);
    if (n > 1) { fprintf(stderr, "more than one %s volume - refusing\n", name); return -1; }
    for (int i = 0; i < nvols; i++)       /* the role must be ours alone: the kernel mounts the first match */
        if (vols[i].role == role && strcmp(vols[i].name, name)) {
            fprintf(stderr, "%s (%s) already has role %ld - refusing to create %s\n", vols[i].name, vols[i].bsd, role, name);
            return -1;
        }
    if (n == 0) {
        const char *nf[] = { "/sbin/newfs_apfs", "-A", "-R", roleletter, "-v", name, "/dev/disk0s1", NULL };
        if (run(nf) != 0) {
            char c[80]; snprintf(c, sizeof c, "/dev/%s", cont);
            const char *nf2[] = { "/sbin/newfs_apfs", "-A", "-R", roleletter, "-v", name, c, NULL };
            if (run(nf2) != 0) { fprintf(stderr, "newfs_apfs %s failed\n", name); return -1; }
        }
        sleep(2);
        list_volumes(0);
        v = named(name, &n);
        if (n != 1) { fprintf(stderr, "%s not found after newfs_apfs\n", name); return -1; }
    }
    if (!in_container(v, cont)) { fprintf(stderr, "%s (%s) is not in the System container %s\n", name, v->bsd, cont); return -1; }
    if (v->role != role) { fprintf(stderr, "%s (%s) has role %ld, expected %ld - refusing\n", name, v->bsd, v->role, role); return -1; }
    return 0;
}

static int do_create(void) {
    if (list_volumes(1) < 1) return 1;
    const char *cont = system_container(); if (!cont) return 1;
    if (create_one(SYSNAME, "v", SYSROLE, cont) || create_one(DATANAME, "n", DATAROLE, cont)) return 1;
    list_volumes(1);
    int n; struct vol *s = named(SYSNAME, &n), *d = named(DATANAME, &n);
    printf("OS2SYS %s\nOS2DATA %s\n", s->bsd, d->bsd);
    return 0;
}

static int do_delete(void) {
    if (list_volumes(1) < 1) return 1;
    const char *cont = system_container(); if (!cont) return 1;
    void *h = dlopen("/System/Library/PrivateFrameworks/APFS.framework/APFS", RTLD_NOW);
    int (*del)(const char *) = h ? (int (*)(const char *))dlsym(h, "APFSVolumeDelete") : NULL;
    if (!del) { fprintf(stderr, "APFSVolumeDelete unavailable (%s)\n", dlerror()); return 1; }
    const char *names[] = { SYSNAME, DATANAME }; long roles[] = { SYSROLE, DATAROLE };
    char todel[2][64]; int k = 0;
    for (int i = 0; i < 2; i++) {               /* check both before deleting anything */
        int n; struct vol *v = named(names[i], &n);
        if (n == 0) { printf("%s: not present\n", names[i]); continue; }
        if (n > 1) { fprintf(stderr, "more than one %s volume - refusing\n", names[i]); return 1; }
        if (!in_container(v, cont)) { fprintf(stderr, "%s (%s) not in the System container - refusing\n", names[i], v->bsd); return 1; }
        if (v->role != roles[i]) { fprintf(stderr, "%s (%s) has role %ld, expected %ld - refusing\n", names[i], v->bsd, v->role, roles[i]); return 1; }
        if (is_mounted(v->bsd)) { fprintf(stderr, "%s (%s) is mounted - unmount it first\n", names[i], v->bsd); return 1; }
        strlcpy(todel[k++], v->bsd, sizeof todel[0]);
    }
    for (int i = 0; i < k; i++) {
        int r = del(todel[i]);
        printf("APFSVolumeDelete(%s) -> 0x%x\n", todel[i], r);
        if (r) return 1;
    }
    sleep(1);
    list_volumes(1);
    int n1, n2; named(SYSNAME, &n1); named(DATANAME, &n2);
    return (n1 || n2) ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: os2vol list|create|delete\n"); return 2; }
    if (!strcmp(argv[1], "list")) return list_volumes(1) < 1;
    if (!strcmp(argv[1], "create")) return do_create();
    if (!strcmp(argv[1], "delete")) return do_delete();
    fprintf(stderr, "unknown command %s\n", argv[1]);
    return 2;
}
