/* mkb: print MobileKeyBag lock state and unlocked-since-boot flags */
#include <stdio.h>
#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>
int main(void) {
    void *h = dlopen("/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag", RTLD_NOW);
    int (*lockstate)(CFDictionaryRef) = dlsym(h, "MKBGetDeviceLockState");
    int (*unlockedsince)(void) = dlsym(h, "MKBDeviceUnlockedSinceBoot");
    int (*userunlocked)(void) = dlsym(h, "MKBUserUnlockedSinceBoot");
    CFDictionaryRef (*status)(CFDictionaryRef) = dlsym(h, "MKBGetDeviceLockStateInfo");
    setvbuf(stdout, NULL, _IONBF, 0);
    if (lockstate) printf("MKBGetDeviceLockState = %d\n", lockstate(NULL));
    if (unlockedsince) printf("MKBDeviceUnlockedSinceBoot = %d\n", unlockedsince());
    if (userunlocked) printf("MKBUserUnlockedSinceBoot = %d\n", userunlocked());
    if (status) { CFDictionaryRef d = status(NULL); if (d) CFShow(d); }
    return 0;
}
