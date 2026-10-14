#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include "keychain.h"

static NSDictionary *item_query(const char *serviceCStr, const char *keyCStr) {
    return @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: [NSString stringWithUTF8String:serviceCStr],
        (__bridge id)kSecAttrAccount: [NSString stringWithUTF8String:keyCStr]
    };
}

int kc_set_item(const char *serviceCStr, const char *keyCStr, const char *valueCStr) {
    @autoreleasepool {
        NSDictionary *query = item_query(serviceCStr, keyCStr);
        SecItemDelete((__bridge CFDictionaryRef)query);

        NSMutableDictionary *attrs = [query mutableCopy];
        attrs[(__bridge id)kSecValueData] =
            [[NSString stringWithUTF8String:valueCStr] dataUsingEncoding:NSUTF8StringEncoding];

        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
        return (status == errSecSuccess) ? 0 : (int)status;
    }
}

int kc_get_item(const char *serviceCStr, const char *keyCStr, char **outStr) {
    @autoreleasepool {
        if (!outStr) return -1;
        *outStr = NULL;

        NSMutableDictionary *query = [item_query(serviceCStr, keyCStr) mutableCopy];
        query[(__bridge id)kSecReturnData] = @YES;
        query[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;

        CFTypeRef dataRef = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &dataRef);
        if (status != errSecSuccess) {
            return (int)status;
        }

        NSData *data = (__bridge_transfer NSData *)dataRef;
        NSString *value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (!value) {
            return -2; // not UTF-8
        }

        *outStr = strdup([value UTF8String]);
        return 0;
    }
}

int kc_delete_item(const char *serviceCStr, const char *keyCStr) {
    @autoreleasepool {
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)item_query(serviceCStr, keyCStr));
        return (status == errSecSuccess || status == errSecItemNotFound) ? 0 : (int)status;
    }
}

char *kc_error_message(int status) {
    @autoreleasepool {
        CFStringRef msg = SecCopyErrorMessageString(status, NULL);
        if (!msg) return NULL;

        NSString *str = (__bridge_transfer NSString *)msg;
        return strdup([str UTF8String]);
    }
}
