/* lsq: LaunchServices query tool. -l lists installed apps, -rebuild <system> <internal> <user> rebuilds the
 * app databases, -unreg <bundle path> unregisters an app, otherwise each argument is looked up as a bundle id. */
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    @autoreleasepool {
        id ws = ((id (*)(id, SEL))objc_msgSend)((id)objc_getClass("LSApplicationWorkspace"), sel_registerName("defaultWorkspace"));
        if (argc > 1 && !strcmp(argv[1], "-rebuild")) {   // -rebuild <system> <internal> <user>
            BOOL s = atoi(argv[2]), i = atoi(argv[3]), u = atoi(argv[4]);
            BOOL ok = ((BOOL (*)(id, SEL, BOOL, BOOL, BOOL))objc_msgSend)(ws, sel_registerName("_LSPrivateRebuildApplicationDatabasesForSystemApps:internal:user:"), s, i, u);
            printf("rebuild(system=%d internal=%d user=%d) -> %d\n", s, i, u, ok);
            return 0;
        }
        if (argc > 2 && !strcmp(argv[1], "-unreg")) {   // -unreg <bundle path>
            BOOL ok = ((BOOL (*)(id, SEL, id))objc_msgSend)(ws, sel_registerName("unregisterApplication:"), [NSURL fileURLWithPath:@(argv[2])]);
            printf("unregister %s -> %d\n", argv[2], ok);
            return !ok;
        }
        NSArray *apps = ((id (*)(id, SEL))objc_msgSend)(ws, sel_registerName("allInstalledApplications"));
        printf("installed apps: %lu\n", (unsigned long)apps.count);
        if (argc > 1 && !strcmp(argv[1], "-l")) {
            for (id a in apps) printf("  %s  %s\n", [[a valueForKey:@"bundleIdentifier"] UTF8String], [[[a valueForKey:@"bundleURL"] path] UTF8String]);
            return 0;
        }
        SEL q = sel_registerName("bundleRecordWithBundleIdentifier:allowPlaceholder:error:");
        for (int k = 1; k < argc; k++) {
            NSError *e = nil;
            id r = ((id (*)(id, SEL, id, BOOL, NSError **))objc_msgSend)((id)objc_getClass("LSBundleRecord"), q, @(argv[k]), YES, &e);
            if (r) printf("%-10s %s -> %s\n", class_getName(object_getClass(r)), argv[k], [[[r valueForKey:@"URL"] path] UTF8String]);
            else printf("MISS  %s (%ld)\n", argv[k], (long)e.code);
        }
    }
}
