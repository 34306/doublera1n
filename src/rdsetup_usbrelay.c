#include <arpa/inet.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef RELAY_PORT
#define RELAY_PORT 2233
#endif
#ifndef RDSETUP_PATH
#define RDSETUP_PATH "/usr/local/bin/rdsetup"
#endif
#ifndef INITIAL_LOG_PATH
#define INITIAL_LOG_PATH "/mnt2/dualboot-setup.log"
#endif

#define MAX_TRANSCRIPT (8u * 1024u * 1024u)
#define MAX_INITIAL (64u * 1024u)

extern CFTypeRef IOUSBDeviceDescriptionCreateWithType(CFAllocatorRef, CFStringRef);
extern void IOUSBDeviceDescriptionSetSerialString(CFTypeRef, CFStringRef);
extern IOReturn IOUSBDeviceControllerCreate(CFAllocatorRef, CFTypeRef *);
extern IOReturn IOUSBDeviceControllerSetDescription(CFTypeRef, CFTypeRef);

static int enable_usb_mux(void) {
    CFTypeRef description = IOUSBDeviceDescriptionCreateWithType(kCFAllocatorDefault, CFSTR("standardMuxOnly"));
    if (!description) return -1;
    IOUSBDeviceDescriptionSetSerialString(description, CFSTR("doublera1n USB setup"));

    CFTypeRef controller = NULL;
    IOReturn status = kIOReturnError;
    for (int attempt = 0; attempt < 10; attempt++) {
        status = IOUSBDeviceControllerCreate(kCFAllocatorDefault, &controller);
        if (status == kIOReturnSuccess && controller) break;
        sleep(3);
    }
    if (status != kIOReturnSuccess || !controller) {
        CFRelease(description);
        return -1;
    }
    status = IOUSBDeviceControllerSetDescription(controller, description);
    CFRelease(description);
    CFRelease(controller);
    if (status != kIOReturnSuccess) return -1;

    for (int attempt = 0; attempt < 10; attempt++) {
        io_service_t mux = IOServiceGetMatchingService(0, IOServiceMatching("AppleUSBDeviceMux"));
        if (mux) {
            IOObjectRelease(mux);
            return 0;
        }
        sleep(1);
    }
    return -1;
}

static char transcript[MAX_TRANSCRIPT + 1];
static size_t transcript_len;
static char initial[MAX_INITIAL];
static size_t initial_len;
static int initial_captured;
static int initial_needed;
static size_t initial_scan_pos;
static int transcript_overflow;

static void write_all(int fd, const void *data, size_t len) {
    const char *p = (const char *)data;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n > 0) { p += n; len -= (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        break;
    }
}

static void capture_initial_if_needed(void) {
    if (initial_captured) return;
    if (!initial_needed) {
        size_t start = initial_scan_pos > 64 ? initial_scan_pos - 64 : 0;
        initial_needed = strstr(transcript + start, "DataB already set up - template copy skipped") != NULL;
        initial_scan_pos = transcript_len;
    }
    if (!initial_needed) return;
    int fd = open(INITIAL_LOG_PATH, O_RDONLY);
    if (fd < 0) return;
    ssize_t n = read(fd, initial, sizeof initial);
    close(fd);
    if (n > 0) { initial_len = (size_t)n; initial_captured = 1; }
}

static int listen_loopback(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(RELAY_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(fd, 4) < 0) {
        close(fd); return -1;
    }
    return fd;
}

static int serve_snapshot(int listener) {
    int fd = accept(listener, NULL, NULL);
    if (fd < 0) return 0;
    struct timeval timeout = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    char header[96];
    int n = snprintf(header, sizeof header, "DBUSB1 %zu %zu %d\n",
                     initial_len, transcript_len, transcript_overflow);
    if (n > 0 && (size_t)n < sizeof header) {
        write_all(fd, header, (size_t)n);
        if (initial_len) write_all(fd, initial, initial_len);
        if (transcript_len) write_all(fd, transcript, transcript_len);
    }
    close(fd);
    return 1;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    if (enable_usb_mux() != 0) {
        const char msg[] = "[usbrelay] cannot enable AppleUSBDeviceMux\n";
        write_all(STDOUT_FILENO, msg, sizeof msg - 1);
        return 1;
    }
    int listener = listen_loopback();
    if (listener < 0) {
        const char msg[] = "[usbrelay] cannot listen on loopback port 2233\n";
        write_all(STDOUT_FILENO, msg, sizeof msg - 1);
        return 1;
    }

    while (!serve_snapshot(listener)) {
        if (errno != EINTR) return 1;
    }
    int pipefd[2];
    if (pipe(pipefd) < 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(pipefd[0]);
        if (listener >= 0) close(listener);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl(RDSETUP_PATH, RDSETUP_PATH, (char *)NULL);
        dprintf(STDERR_FILENO, "[usbrelay] cannot exec rdsetup: %s\n", strerror(errno));
        _exit(127);
    }
    close(pipefd[1]);
    int source_open = 1;
    for (;;) {
        fd_set ready;
        FD_ZERO(&ready);
        if (source_open) FD_SET(pipefd[0], &ready);
        if (listener >= 0) FD_SET(listener, &ready);
        int maxfd = pipefd[0] > listener ? pipefd[0] : listener;
        if (!source_open && listener < 0) break;
        int n = select(maxfd + 1, &ready, NULL, NULL, NULL);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (source_open && FD_ISSET(pipefd[0], &ready)) {
            char chunk[8192];
            ssize_t got = read(pipefd[0], chunk, sizeof chunk);
            if (got > 0) {
                write_all(STDOUT_FILENO, chunk, (size_t)got);
                if (!transcript_overflow && transcript_len + (size_t)got <= MAX_TRANSCRIPT) {
                    memcpy(transcript + transcript_len, chunk, (size_t)got);
                    transcript_len += (size_t)got;
                    transcript[transcript_len] = '\0';
                    capture_initial_if_needed();
                } else if (!transcript_overflow) {
                    transcript_overflow = 1;
                    const char msg[] = "[usbrelay] transcript overflow\n";
                    write_all(STDOUT_FILENO, msg, sizeof msg - 1);
                }
            } else if (got == 0) {
                close(pipefd[0]); source_open = 0;
                int status = 0;
                while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
                const char msg[] = "[usbrelay] rdsetup exited before the phone was rebooted\n";
                write_all(STDOUT_FILENO, msg, sizeof msg - 1);
                if (transcript_len + sizeof msg - 1 <= MAX_TRANSCRIPT) {
                    memcpy(transcript + transcript_len, msg, sizeof msg - 1);
                    transcript_len += sizeof msg - 1;
                    transcript[transcript_len] = '\0';
                }
            }
        }
        if (listener >= 0 && FD_ISSET(listener, &ready)) serve_snapshot(listener);
    }
    return 0;
}
