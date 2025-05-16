#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <libproc.h>
#import <unistd.h>

int kc_set_item(const char *serviceCStr, const char *keyCStr, const char *valueCStr) {
    @autoreleasepool {
        NSString *service = [NSString stringWithUTF8String:serviceCStr];
        NSString *key = [NSString stringWithUTF8String:keyCStr];
        NSString *value = [NSString stringWithUTF8String:valueCStr];
        NSData *valueData = [value dataUsingEncoding:NSUTF8StringEncoding];

        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: service,
            (__bridge id)kSecAttrAccount: key
        };

        SecItemDelete((__bridge CFDictionaryRef)query);

        NSDictionary *attrs = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: service,
            (__bridge id)kSecAttrAccount: key,
            (__bridge id)kSecValueData: valueData
        };

        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attrs, NULL);
        return (status == errSecSuccess) ? 0 : (int)status;
    }
}

int kc_get_item(const char *serviceCStr, const char *keyCStr, char **outStr) {
    @autoreleasepool {
        if (!outStr) return -1;

        *outStr = NULL;

        NSString *service = [NSString stringWithUTF8String:serviceCStr];
        NSString *key = [NSString stringWithUTF8String:keyCStr];

        NSDictionary *query = @{
            (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService: service,
            (__bridge id)kSecAttrAccount: key,
            (__bridge id)kSecReturnData: @YES,
            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
        };

        CFTypeRef dataRef = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &dataRef);
        if (status != errSecSuccess) {
            return (int)status;
        }

        NSData *data = (__bridge_transfer NSData *)dataRef;
        NSString *value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (!value) {
            return -2; // Custom error: decoding failure
        }

        const char *utf8 = [value UTF8String];
        *outStr = malloc(strlen(utf8) + 1);
        strcpy(*outStr, utf8);
        return 0; // Success
    }
}

int kc_authenticate_user(const char *reasonCStr) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        NSString *reason = [NSString stringWithUTF8String:reasonCStr];

        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error]) {
            return -1;
        }

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        __block int result = 1;

        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                localizedReason:reason
                          reply:^(BOOL success, NSError *error) {
            result = success ? 0 : 1;
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return result;
    }
}

const char *kc_error_message(OSStatus status) {
    @autoreleasepool {
        CFStringRef msg = SecCopyErrorMessageString(status, NULL);
        if (!msg) return NULL;

        NSString *str = (__bridge_transfer NSString *)msg;
        return strdup([str UTF8String]);
    }
}

const char *kc_parent_process_name(void) {
    @autoreleasepool {
        pid_t ppid = getppid();
        char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};

        int ret = proc_pidpath(ppid, pathBuffer, sizeof(pathBuffer));
        if (ret <= 0) {
            return strdup("(unknown)");
        }

        NSString *fullPath = [NSString stringWithUTF8String:pathBuffer];
        return strdup([fullPath UTF8String]);  // caller must free
    }
}