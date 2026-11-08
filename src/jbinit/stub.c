/* /sbin/launchd on the jb ramdisk: never actually runs — it only names /usr/lib/dyld (jbinit)
 * as its dynamic linker, which the kernel loads and starts as PID 1. */
int main(void) { for (;;) ; }
