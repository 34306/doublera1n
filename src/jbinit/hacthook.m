/*
 * hacthook.dylib — offline "hactivation" for OS B (SEP-less: real activation needs a SEP-attested key).
 * Loaded into mobileactivationd only (no-op in every other process).
 *   -[DeviceType should_hactivate] -> YES
 *   -[MobileActivationDaemon getActivationStateWithCompletionBlock:] -> {ActivationState: Activated}
 *     (the stock method answers "Unavailable" until data migration completed, else data_ark's value)
 * mobileactivationd's own code then takes the path Apple uses for internal / demoted devices:
 *   "_dealwith_activation: Hactivation is enabled, short circuiting activation state to Activated."
 * Applies the mobileactivationd "should-hactivate" patch at runtime via the ObjC runtime, without modifying the sealed System volume.
 */
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

static void con(const char *s) {
    int c = open("/dev/console", O_WRONLY | O_NOCTTY);
    if (c >= 0) { dprintf(c, "[hacthook] %s\n", s); close(c); }
}

static BOOL yes_imp(id self, SEL _cmd) { return YES; }

static void state_imp(id self, SEL _cmd, void (^cb)(NSDictionary *, NSError *)) {
    if (cb) cb(@{ @"ActivationState": @"Activated" }, nil);
}

__attribute__((constructor)) static void init(void) {
    const char *name = getprogname();
    if (!name || strcmp(name, "mobileactivationd") != 0) return;
    Class c = objc_getClass("DeviceType");
    Method m = c ? class_getInstanceMethod(c, sel_registerName("should_hactivate")) : NULL;
    if (!m) { con("DeviceType/should_hactivate not found"); return; }
    method_setImplementation(m, (IMP)yes_imp);
    con("mobileactivationd: -[DeviceType should_hactivate] -> YES");
    Class d = objc_getClass("MobileActivationDaemon");
    Method g = d ? class_getInstanceMethod(d, sel_registerName("getActivationStateWithCompletionBlock:")) : NULL;
    if (g) { method_setImplementation(g, (IMP)state_imp); con("mobileactivationd: getActivationStateWithCompletionBlock: -> Activated"); }
    else con("MobileActivationDaemon/getActivationStateWithCompletionBlock: not found");
}
