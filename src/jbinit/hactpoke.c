/* hactpoke [pid]: set -[DeviceType should_hactivate] (ivar +0x15 of the singleton stored at
 * __bss 0x100400c08, mobileactivationd 24B119) to YES in the running daemon via its task port.
 * Data write only - no code is modified or injected. Prints old/new values. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
kern_return_t task_for_pid(mach_port_t, int, mach_port_t *);
kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
kern_return_t mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);
int proc_listallpids(void *, int); int proc_pidpath(int, void *, uint32_t);
#define STATIC_OFF 0x400c08ULL   /* _sharedInstance.device_type - 0x100000000 */
#define IVAR_OFF   0x15          /* -[DeviceType should_hactivate]: LDRB W0,[X0,#0x15] */
static int rd(mach_port_t t, uint64_t a, void *b, size_t n) { mach_vm_size_t o = 0; return mach_vm_read_overwrite(t, a, n, (mach_vm_address_t)b, &o) || o != n; }
static int find_pid(const char *path) { static int p[4096]; int n = proc_listallpids(p, sizeof p); char b[1024];
  for (int i = 0; i < n; i++) if (proc_pidpath(p[i], b, sizeof b) > 0 && !strcmp(b, path)) return p[i]; return -1; }
int main(int c, char **v) {
  int pid = c > 1 ? atoi(v[1]) : find_pid("/usr/libexec/mobileactivationd");
  if (pid <= 0) { puts("mobileactivationd not running"); return 1; }
  mach_port_t t; kern_return_t kr = task_for_pid(mach_task_self(), pid, &t);
  if (kr) { printf("task_for_pid(%d) -> %d\n", pid, kr); return 1; }
  struct task_dyld_info di; mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
  task_info(t, TASK_DYLD_INFO, (task_info_t)&di, &cnt);
  struct dyld_all_image_infos ai; struct dyld_image_info ii; char path[256] = {0};
  if (rd(t, di.all_image_info_addr, &ai, sizeof ai) || rd(t, (uint64_t)ai.infoArray, &ii, sizeof ii)) { puts("dyld info read failed"); return 1; }
  rd(t, (uint64_t)ii.imageFilePath, path, sizeof path - 1);
  uint64_t base = (uint64_t)ii.imageLoadAddress;
  if (!strstr(path, "mobileactivationd")) { printf("first image is %s, not mobileactivationd\n", path); return 1; }
  uint64_t obj = 0; rd(t, base + STATIC_OFF, &obj, 8);
  printf("pid %d base 0x%llx DeviceType singleton 0x%llx\n", pid, base, obj);
  if (!obj) { puts("singleton not created yet"); return 2; }
  uint8_t old = 0, one = 1, now = 0; rd(t, obj + IVAR_OFF, &old, 1);
  kr = mach_vm_write(t, obj + IVAR_OFF, (vm_offset_t)&one, 1);
  rd(t, obj + IVAR_OFF, &now, 1);
  printf("should_hactivate %u -> %u (write kr %d)\n", old, now, kr);
  return now == 1 ? 0 : 1;
}
