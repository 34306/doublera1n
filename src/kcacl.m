#import <Foundation/Foundation.h>
#import <Security/Security.h>
// add + read back a keychain item protected by an access control with a user-presence constraint
int main(void) {
    @autoreleasepool {
        setvbuf(stdout, NULL, _IONBF, 0);
        NSDictionary *base = @{ (id)kSecClass: (id)kSecClassGenericPassword, (id)kSecAttrService: @"dualboot.acltest",
                                (id)kSecAttrAccount: @"probe", (id)kSecAttrAccessGroup: @"dualboot.test" };
        SecItemDelete((__bridge CFDictionaryRef)base);
        CFErrorRef err = NULL;
        SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL, kSecAttrAccessibleWhenUnlocked,
                                                                 kSecAccessControlUserPresence, &err);
        NSMutableDictionary *add = [base mutableCopy];
        add[(id)kSecAttrAccessControl] = (__bridge id)ac;
        add[(id)kSecValueData] = [@"secret-123" dataUsingEncoding:NSUTF8StringEncoding];
        OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
        printf("add with ACL(UserPresence): %d\n", (int)st);
        NSMutableDictionary *q = [base mutableCopy];
        q[(id)kSecReturnData] = @YES;
        CFTypeRef out = NULL;
        st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
        printf("read back: %d %s\n", (int)st, out ? [[[NSString alloc] initWithData:(__bridge NSData *)out encoding:NSUTF8StringEncoding] UTF8String] : "-");
        printf("delete: %d\n", (int)SecItemDelete((__bridge CFDictionaryRef)base));
    }
    return 0;
}
