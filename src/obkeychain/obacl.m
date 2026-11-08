/*
 * obacl - part of obkeychain.dylib for the dualboot OS B (SEP-less).
 *
 * OS B has no AppleCredentialManager/SEP, so no client can ever obtain a bound ACM context. securityd's
 * -[SecDbKeychainItemV7 wrapToAKS:withKeybag:accessControl:acmContext:error:] therefore rejects every write of an
 * item whose access control carries constraints with errSecAuthNeeded (-25330) - e.g. accountsd storing the
 * iCloud (idms) token, which makes iCloud sign-in fail - and an AKS ref key could not be served anyway.
 *
 * When the access control has constraints, call the original method with a constraint-free access control that
 * keeps the same protection class: securityd then stores a REGULAR class-wrapped key (wrapped key type 0) through
 * aks_wrap_key, which obkeychain serves with its software class keys. -[SecDbKeychainItemV7 unwrapFromAKS:...]
 * picks the decrypt path from the stored key type, so these items read back without ACM.
 *
 * Tradeoff (same stance as obkeychain/obpair): the per-item user-presence constraint is not enforced on OS B -
 * it cannot be without a SEP. Gated by the obkeychain marker; only active inside securityd.
 */
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <os/log.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#ifndef OBKEYCHAIN_MARKER_SYSTEM
#define OBKEYCHAIN_MARKER_SYSTEM "/usr/lib/.obkeychain"
#endif

extern SecAccessControlRef SecAccessControlCreate(CFAllocatorRef allocator, CFErrorRef *error);
extern bool SecAccessControlSetProtection(SecAccessControlRef access_control, CFTypeRef protection, CFErrorRef *error);
extern CFTypeRef SecAccessControlGetProtection(SecAccessControlRef access_control);
extern CFDictionaryRef SecAccessControlGetConstraints(SecAccessControlRef access_control);

typedef id (*wrap_fn)(id, SEL, id, int, SecAccessControlRef, id, id *);
static wrap_fn orig_wrap;

static bool obacl_marker(void)
{
    struct stat st;
    return stat(OBKEYCHAIN_MARKER_SYSTEM, &st) == 0;
}

static id obacl_wrap(id self, SEL cmd, id key, int keybag, SecAccessControlRef ac, id acm, id *error)
{
    if (ac != NULL && obacl_marker()) {
        CFDictionaryRef constraints = SecAccessControlGetConstraints(ac);
        CFTypeRef protection = SecAccessControlGetProtection(ac);
        if (constraints != NULL && CFDictionaryGetCount(constraints) > 0 && protection != NULL) {
            SecAccessControlRef plain = SecAccessControlCreate(kCFAllocatorDefault, NULL);
            if (plain != NULL && SecAccessControlSetProtection(plain, protection, NULL)
                && SecAccessControlGetConstraints(plain) == NULL) {
                os_log(OS_LOG_DEFAULT, "obacl: ACL item without ACM -> class-wrapped key (protection %{public}@, acm %d)",
                       protection, acm != nil);
                id r = orig_wrap(self, cmd, key, keybag, plain, acm, error);
                CFRelease(plain);
                return r;
            }
            if (plain != NULL)
                CFRelease(plain);
        }
    }
    return orig_wrap(self, cmd, key, keybag, ac, acm, error);
}

__attribute__((constructor)) static void obacl_init(void)
{
    const char *name = getprogname();
    if (name == NULL || strcmp(name, "securityd") != 0)
        return;
    Class c = objc_getClass("SecDbKeychainItemV7");
    SEL s = sel_registerName("wrapToAKS:withKeybag:accessControl:acmContext:error:");
    Method m = c ? class_getInstanceMethod(c, s) : NULL;
    if (m == NULL) {
        os_log_error(OS_LOG_DEFAULT, "obacl: -[SecDbKeychainItemV7 wrapToAKS:...] not found - inactive");
        return;
    }
    orig_wrap = (wrap_fn)method_setImplementation(m, (IMP)obacl_wrap);
    os_log(OS_LOG_DEFAULT, "obacl: installed (marker %{public}s)", obacl_marker() ? "on" : "off");
}
