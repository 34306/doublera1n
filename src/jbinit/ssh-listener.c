#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct process_info {
    uint32_t pid, ppid, pgid, status;
    char name[16];
    uint32_t flags, uid, gid, ruid, rgid, svuid, svgid, reserved;
};

_Static_assert(sizeof(struct process_info) == 64, "process_info ABI");
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int size);
int proc_pidpath(int pid, void *buffer, uint32_t size);
int csops(pid_t pid, unsigned int operation, void *buffer, size_t size);

static int identity_matches(int pid, const char *expected) {
    struct {
        uint32_t magic, length;
        char value[256];
    } identity = {0};
    if (csops(pid, 11, &identity, sizeof(identity)) != 0) {
        int error = errno;
        fprintf(stderr, "Cannot read code identity for PID %d: errno %d (%s).\n", pid, error, strerror(error));
        return 0;
    }
    size_t size = strlen(expected) + 1;
    if (identity.magic != 0 || ntohl(identity.length) != 8 + size ||
        memcmp(identity.value, expected, size) != 0) {
        fprintf(stderr, "PID %d does not have the expected %s code identity.\n", pid, expected);
        return 0;
    }
    return 1;
}

static int inspect(int pid, const char *role, const char *expected, struct process_info *info, char path[4096]) {
    memset(info, 0, sizeof(*info));
    memset(path, 0, 4096);
    errno = 0;
    int size = proc_pidinfo(pid, 13, 0, info, sizeof(*info));
    if (size != (int)sizeof(*info)) {
        int error = errno;
        fprintf(stderr, "Cannot inspect SSH %s PID %d: proc_pidinfo returned %d/%zu bytes, errno %d (%s).\n",
                role, pid, size, sizeof(*info), error, strerror(error));
        return -1;
    }
    if (info->pid != (uint32_t)pid || info->uid != 0) {
        fprintf(stderr, "Cannot verify SSH %s PID %d: reported pid=%u uid=%u ppid=%u name=%.16s.\n",
                role, pid, info->pid, info->uid, info->ppid, info->name);
        return -1;
    }
    errno = 0;
    int length = proc_pidpath(pid, path, 4096);
    if (length <= 0 || !path[0] || !memchr(path, 0, 4096)) {
        int error = errno;
        if (length <= 0 && error == ENOENT &&
            strncmp(info->name, expected, sizeof(info->name)) == 0 && identity_matches(pid, expected)) {
            path[0] = 0;
            return 0;
        }
        fprintf(stderr, "Cannot resolve SSH %s PID %d: proc_pidpath returned %d, errno %d (%s); ppid=%u name=%.16s.\n",
                role, pid, length, error, strerror(error), info->ppid, info->name);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (getuid() != 0 || argc != 2 || !argv[1][0] ||
        strspn(argv[1], "0123456789") != strlen(argv[1])) {
        fputs("Expected an SSH listener PID; run as root.\n", stderr);
        return 1;
    }
    errno = 0;
    long pid = strtol(argv[1], NULL, 10);
    if (errno || pid <= 1 || pid > INT_MAX) {
        fputs("Invalid SSH listener PID.\n", stderr);
        return 1;
    }
    struct process_info listener, supervisor;
    char path[4096];
    if (inspect((int)pid, "listener", "sshd", &listener, path)) return 1;
    if (path[0] && strcmp(path, "/var/jb/usr/sbin/sshd") && strcmp(path, "/private/var/jb/usr/sbin/sshd")) {
        fputs("sshd.pid does not identify the SSH daemon.\n", stderr);
        return 1;
    }
    if (listener.ppid < 1 || listener.ppid > INT_MAX || listener.ppid == listener.pid) {
        fputs("Invalid SSH supervisor PID.\n", stderr);
        return 1;
    }
    if (listener.ppid != 1) {
        if (inspect((int)listener.ppid, "supervisor", "jbloader", &supervisor, path)) return 1;
        const char *name = strrchr(path, '/');
        if (path[0] && (!name || strcmp(name + 1, "jbloader"))) {
            fputs("SSH has an unexpected supervisor.\n", stderr);
            return 1;
        }
    }
    printf("%u\n", listener.ppid);
    return 0;
}
