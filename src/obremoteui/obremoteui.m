/*
 * obremoteui.dylib - let RemoteUI pages use WebKit on 2nd Data.
 *
 * 2nd Data's DeviceTree carries /product/boot-ios-diagnostics=1 (SEP-less boot), so MobileGestalt answers
 * InDiagnosticsMode = true (libMobileGestalt: /chosen/osenvironment == "diagnostics" || /product has
 * boot-ios-diagnostics). +[RUIPlatform assertWebkitAllowed] then throws "Webkit is not allowed in diagnostics mode"
 * as soon as a RemoteUI page contains a web view: Setup crashes on "Don't use Apple Account" (terms page) and
 * restarts at "Hello". WebKit is complete on the stock System volume, so the assertion is turned into a no-op.
 * Only that one method changes; every other InDiagnosticsMode user keeps its answer.
 *
 * Loaded by ElleKit's TweakLoader into UIKit processes; RemoteUI may be loaded later, so the hook is applied from a
 * dyld add-image callback the first time RUIPlatform exists.
 */
#include <objc/runtime.h>
#include <mach-o/dyld.h>
#include <stdatomic.h>
#include <syslog.h>

static atomic_int hooked;

static void webkit_allowed(id self, SEL _cmd) { (void)self; (void)_cmd; }

static void try_hook(const struct mach_header *mh, intptr_t slide) {
    (void)mh; (void)slide;
    if (atomic_load(&hooked)) return;
    Class c = objc_getClass("RUIPlatform");
    if (!c) return;
    Method m = class_getClassMethod(c, sel_registerName("assertWebkitAllowed"));
    if (!m || atomic_exchange(&hooked, 1)) return;
    method_setImplementation(m, (IMP)webkit_allowed);
    syslog(LOG_NOTICE, "obremoteui: +[RUIPlatform assertWebkitAllowed] -> no-op");
}

__attribute__((constructor)) static void init(void) {
    _dyld_register_func_for_add_image(try_hook);   /* runs for every loaded image now, then for each new one */
}
