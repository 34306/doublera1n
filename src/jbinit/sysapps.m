/* sysapps: install the removable system apps staged in /private/var/staged_system_apps exactly like a
 * fresh restore does: load Apple's SystemAppMigrator.migrator (DataMigration plugin) and run its
 * -performMigration in this process, which carries the migration plugin host's entitlements
 * (com.apple.private.mobileinstall.allowedSPI: InstallForDataMigrator, UpdateSystemAppState, ...).
 *   sysapps                       fresh install (didUpgrade = NO): installs staged apps that are missing
 *   sysapps --upgrade <old build> what an OTA does (didUpgrade = YES, previousBuildVersion = old build): also
 *                                 updates installed system apps from an older build. Used after stock iOS was
 *                                 updated and 2nd Data rebuilt for it (old system apps fail with dyld "Symbol not
 *                                 found" against the new shared cache). */
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <string.h>
int main(int argc, char **argv) {
    @autoreleasepool {
        NSString *path = @"/System/Library/DataClassMigrators/SystemAppMigrator.migrator";
        [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/DataMigration.framework"] load];
        NSBundle *b = [NSBundle bundleWithPath:path];
        NSError *e = nil;
        if (![b loadAndReturnError:&e]) { printf("load: %s\n", e.description.UTF8String); return 1; }
        Class c = b.principalClass;
        printf("principal class: %s\n", c ? class_getName(c) : "(nil)");
        id m = [[c alloc] init];
        unsigned n = 0; objc_property_t *ps = class_copyPropertyList(class_getSuperclass(c), &n);
        for (unsigned i = 0; i < n; i++) printf("  superclass property %s\n", property_getName(ps[i]));
        free(ps);
        BOOL upgrade = argc > 2 && !strcmp(argv[1], "--upgrade");
        if ([m respondsToSelector:NSSelectorFromString(@"setDidUpgrade:")])
            ((void (*)(id, SEL, BOOL))objc_msgSend)(m, NSSelectorFromString(@"setDidUpgrade:"), upgrade);
        if (upgrade) {          /* readonly property backed by the _previousBuildVersion ivar */
            Ivar iv = class_getInstanceVariable(c, "_previousBuildVersion");
            if (iv) object_setIvar(m, iv, [NSString stringWithUTF8String:argv[2]]);
            printf("upgrade mode: didUpgrade = YES, previousBuildVersion = %s%s\n", argv[2], iv ? "" : " (ivar not found)");
        }
        NSDate *t0 = [NSDate date];
        BOOL ok = ((BOOL (*)(id, SEL))objc_msgSend)(m, NSSelectorFromString(@"performMigration"));
        printf("performMigration -> %d (%.1f s)\n", ok, -[t0 timeIntervalSinceNow]);
    }
    return 0;
}
