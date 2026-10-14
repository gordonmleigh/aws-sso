#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

#include "touchid.h"

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
