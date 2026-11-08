/* maactivate: print the activation state, ask mobileactivationd to "unbrick" (handle_unbrick ->
 * dealwith_activation, which short-circuits to Activated when should_hactivate is set - see hactpoke),
 * print the state again. Run with launchd's bootstrap port (bpexec). */
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#import <objc/message.h>
int main(void) {
    @autoreleasepool {
        void *h = dlopen("/System/Library/PrivateFrameworks/MobileActivation.framework/MobileActivation", RTLD_NOW);
        if (!h) { printf("dlopen: %s\n", dlerror()); return 1; }
        id (*getState)(NSError **) = dlsym(h, "MAEGetActivationStateWithError");
        NSError *e = nil;
        printf("state before: %s (%s)\n", [[getState(&e) description] UTF8String], [[e description] UTF8String]);
        Class G = NSClassFromString(@"MadGate");
        id g = [[G alloc] init];
        e = nil;
        BOOL ok = ((BOOL (*)(id, SEL, NSError **))objc_msgSend)(g, NSSelectorFromString(@"unbrickDevice:"), &e);
        printf("unbrickDevice -> %d (%s)\n", ok, [[e description] UTF8String]);
        e = nil;
        printf("state after: %s (%s)\n", [[getState(&e) description] UTF8String], [[e description] UTF8String]);
    }
    return 0;
}
