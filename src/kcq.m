#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <dlfcn.h>
// list Wi-Fi (AirPort) items in the system keychain: account, creation/modification dates (never the secret)
int main(void) {
    @autoreleasepool {
        setvbuf(stdout, NULL, _IONBF, 0);
        for (int sys = 0; sys < 2; sys++) {
            NSMutableDictionary *q = [@{ (id)kSecClass: (id)kSecClassGenericPassword, (id)kSecAttrSynchronizable: (id)kSecAttrSynchronizableAny,
                                         (id)kSecReturnAttributes: @YES, (id)kSecMatchLimit: (id)kSecMatchLimitAll } mutableCopy];
            if (sys) { CFStringRef *k = dlsym(RTLD_DEFAULT, "kSecUseSystemKeychain"); if (!k) { printf("no kSecUseSystemKeychain\n"); continue; } q[(__bridge id)*k] = @YES; }
            CFTypeRef res = NULL; OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
            printf("%s keychain: status %d\n", sys ? "system" : "user", (int)st);
            for (NSDictionary *a in (__bridge NSArray *)res) {
                NSString *sv = [a[@"svce"] description] ?: @"", *ac = [a[@"acct"] description] ?: @"";
                if (![sv containsString:@"AirPort"] && ![ac containsString:@"FPT"] && ![sv.lowercaseString containsString:@"wifi"]) continue;
                printf("   svce=%s sync=%s\n", sv.UTF8String, [[a[@"sync"] description] UTF8String]);
                printf("   acct=%s cdat=%s mdat=%s agrp=%s pdmn=%s\n", [[a[@"acct"] description] UTF8String],
                       [[a[@"cdat"] description] UTF8String], [[a[@"mdat"] description] UTF8String],
                       [[a[@"agrp"] description] UTF8String], [[a[@"pdmn"] description] UTF8String]);
            }
            printf("   (%lu items total in this keychain/group set)\n", (unsigned long)[(__bridge NSArray *)res count]);
            NSMutableDictionary *hist = [NSMutableDictionary dictionary];
            for (NSDictionary *a in (__bridge NSArray *)res) {
                NSString *k = [[a[@"cdat"] description] substringToIndex:16];
                hist[k] = @([hist[k] intValue] + 1);
            }
            for (NSString *k in [hist.allKeys sortedArrayUsingSelector:@selector(compare:)]) printf("     cdat %s  x%d\n", k.UTF8String, [hist[k] intValue]);
        }
    }
    return 0;
}
