/* lsimg <pid> [filter]: list dyld images of a process (task_for_pid + all_image_infos) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
kern_return_t task_for_pid(mach_port_t, int, mach_port_t *);
kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
static int rd(mach_port_t t, uint64_t a, void *b, size_t n) { mach_vm_size_t o = 0; return mach_vm_read_overwrite(t, a, n, (mach_vm_address_t)b, &o) || o != n; }
int main(int c, char **v) {
  mach_port_t t; kern_return_t kr = task_for_pid(mach_task_self(), atoi(v[1]), &t);
  if (kr) { printf("tfp %d\n", kr); return 1; }
  struct task_dyld_info di; mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
  task_info(t, TASK_DYLD_INFO, (task_info_t)&di, &cnt);
  struct dyld_all_image_infos ai; if (rd(t, di.all_image_info_addr, &ai, sizeof ai)) { puts("read aii failed"); return 1; }
  printf("version %u count %u array %p\n", ai.version, ai.infoArrayCount, ai.infoArray);
  for (uint32_t i = 0; i < ai.infoArrayCount && i < 4000; i++) {
    struct dyld_image_info ii; if (rd(t, (uint64_t)ai.infoArray + i * sizeof ii, &ii, sizeof ii)) break;
    char p[512] = {0}; rd(t, (uint64_t)ii.imageFilePath, p, sizeof p - 1);
    if (c < 3 || strstr(p, v[2])) printf("%p %s\n", ii.imageLoadAddress, p);
  }
  return 0;
}
