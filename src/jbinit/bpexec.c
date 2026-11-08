/* bpexec <cmd> [args]: adopt launchd's bootstrap port (via task_for_pid of a launchd child) then exec */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
kern_return_t task_for_pid(mach_port_t, int, mach_port_t *);
int proc_listallpids(void *, int); int proc_pidpath(int, void *, uint32_t);
static int find_pid(const char *path) { static int p[4096]; int n = proc_listallpids(p, sizeof p); char b[1024];
  for (int i = 0; i < n; i++) if (proc_pidpath(p[i], b, sizeof b) > 0 && !strcmp(b, path)) return p[i]; return -1; }
int main(int argc, char **argv) {
  const char *d[] = { "/usr/libexec/lockdownd", "/usr/sbin/wifid", "/usr/libexec/securityd", 0 };
  for (int i = 0; d[i]; i++) {
    int pid = find_pid(d[i]); mach_port_t t = 0, bp = 0;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &t);
    fprintf(stderr, "tfp(%s=%d) -> %d\n", d[i], pid, kr);
    if (kr) continue;
    kr = task_get_special_port(t, TASK_BOOTSTRAP_PORT, &bp);
    fprintf(stderr, "bootstrap -> %d port %x\n", kr, bp);
    if (kr || !MACH_PORT_VALID(bp)) continue;
    task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, bp);
    if (argc > 1) { execv(argv[1], argv + 1); perror("execv"); }
    return 0;
  }
  return 1;
}
