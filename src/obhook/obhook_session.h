#ifndef OBHOOK_SESSION_H
#define OBHOOK_SESSION_H
#include <sys/sysctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#ifndef OBHOOK_ENABLE_PATH
#define OBHOOK_ENABLE_PATH "/var/jb/.obhook_enabled"
#endif

/* A persistent empty flag is unsafe at early boot. Bind permission to the
 * kernel's boot-session UUID, not wall time, PID reuse or a persisted boolean.
 * Unsupported sysctl, unreadable, malformed and previous-boot flags fail closed.
 * No Foundation, heap allocation or stateful lock in launchd's spawn path. */
static int obhook_boot_id(char out[64]) {
    size_t size = 64;
    if (sysctlbyname("kern.bootsessionuuid", out, &size, NULL, 0) ||
        size == 0 || size > 64) return 0;
    out[63] = '\0';
    return strlen(out) == 36;
}

static int obhook_session_enabled(void) {
    char current[64] = {0}, stored[64] = {0};
    if (!obhook_boot_id(current)) return 0;
    int fd = open(OBHOOK_ENABLE_PATH, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return 0;
    ssize_t n = read(fd, stored, sizeof(stored));
    close(fd);
    if (n != 36 && !(n == 37 && stored[36] == '\n')) return 0;
    stored[36] = '\0';
    return !strcmp(current, stored);
}
#endif
