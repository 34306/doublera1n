/* stackdump <pid> [maxthreads]: per thread pc/lr + frame-pointer chain, each as image+offset */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach-o/dyld_images.h>
kern_return_t task_for_pid(mach_port_t, int, mach_port_t *);
kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
static mach_port_t T;
static int rd(uint64_t a, void *b, size_t n) { mach_vm_size_t o = 0; return mach_vm_read_overwrite(T, a, n, (mach_vm_address_t)b, &o) || o != n; }
static struct { uint64_t base; char name[200]; } img[2048]; static int nimg;
static void where(uint64_t a) {
    a &= 0x0000007fffffffffULL; int best = -1;
    for (int i = 0; i < nimg; i++) if (img[i].base <= a && (best < 0 || img[i].base > img[best].base)) best = i;
    if (best >= 0) printf("0x%llx %s+0x%llx\n", a, img[best].name, a - img[best].base); else printf("0x%llx ?\n", a);
}
int main(int c, char **v) {
    if (task_for_pid(mach_task_self(), atoi(v[1]), &T)) { puts("tfp failed"); return 1; }
    int maxt = c > 2 ? atoi(v[2]) : 3;
    struct task_dyld_info di; mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    task_info(T, TASK_DYLD_INFO, (task_info_t)&di, &cnt);
    struct dyld_all_image_infos ai; rd(di.all_image_info_addr, &ai, sizeof ai);
    printf("shared cache slide 0x%llx base 0x%llx\n", (unsigned long long)ai.sharedCacheSlide, (unsigned long long)ai.sharedCacheBaseAddress);
    for (uint32_t i = 0; i < ai.infoArrayCount && nimg < 2048; i++) {
        struct dyld_image_info ii; if (rd((uint64_t)ai.infoArray + i * sizeof ii, &ii, sizeof ii)) break;
        char p[256] = {0}; rd((uint64_t)ii.imageFilePath, p, sizeof p - 1);
        const char *b = strrchr(p, '/'); img[nimg].base = (uint64_t)ii.imageLoadAddress; strncpy(img[nimg].name, b ? b + 1 : p, 199); nimg++;
    }
    thread_act_array_t th; mach_msg_type_number_t nth;
    task_threads(T, &th, &nth);
    for (unsigned t = 0; t < nth && (int)t < maxt; t++) {
        arm_thread_state64_t st; mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
        if (thread_get_state(th[t], ARM_THREAD_STATE64, (thread_state_t)&st, &sc)) continue;
        printf("== thread %u\n pc ", t); where(__darwin_arm_thread_state64_get_pc(st));
        printf(" lr "); where(__darwin_arm_thread_state64_get_lr(st));
        uint64_t fp = __darwin_arm_thread_state64_get_fp(st);
        for (int d = 0; d < 24 && fp; d++) { uint64_t fr[2]; if (rd(fp, fr, 16)) break; printf(" #%02d ", d); where(fr[1]); fp = fr[0]; }
    }
    return 0;
}
