#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <libproc.h>
#import <sys/sysctl.h>

#include "procinfo.h"

int pi_get_bsdinfo(int pid, pi_bsdinfo *out) {
    struct proc_bsdinfo info;

    int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (ret != sizeof(info)) {
        return -1;
    }

    out->ppid = (int)info.pbi_ppid;
    out->start_sec = info.pbi_start_tvsec;
    out->start_usec = info.pbi_start_tvusec;
    return 0;
}

char *pi_get_path(int pid) {
    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};

    int ret = proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));
    if (ret <= 0) {
        return NULL;
    }
    return strdup(pathBuffer); // caller must free
}

// Returns the process arguments as a sequence of NUL-terminated strings, with
// the total length in outLen. Only works for processes owned by the same user.
char *pi_get_args(int pid, int *outLen) {
    int argmax = 0;
    size_t size = sizeof(argmax);
    int mib[3] = {CTL_KERN, KERN_ARGMAX, 0};

    if (sysctl(mib, 2, &argmax, &size, NULL, 0) != 0 || argmax <= 0) {
        return NULL;
    }

    char *buf = malloc(argmax);
    if (!buf) return NULL;

    // layout: int argc, exec path, NUL padding, argv[0..argc), envp...
    mib[1] = KERN_PROCARGS2;
    mib[2] = pid;
    size = (size_t)argmax;
    if (sysctl(mib, 3, buf, &size, NULL, 0) != 0 || size < sizeof(int)) {
        free(buf);
        return NULL;
    }

    int argc;
    memcpy(&argc, buf, sizeof(argc));

    char *end = buf + size;
    char *p = buf + sizeof(argc);

    // skip exec path and padding
    while (p < end && *p != '\0') p++;
    while (p < end && *p == '\0') p++;

    char *argsStart = p;
    for (int i = 0; i < argc && p < end; i++) {
        while (p < end && *p != '\0') p++;
        if (p < end) p++; // include terminator
    }

    int len = (int)(p - argsStart);
    char *result = malloc(len > 0 ? len : 1);
    if (result) {
        memcpy(result, argsStart, len);
        *outLen = len;
    }
    free(buf);
    return result; // caller must free
}

static NSString *describeSigner(SecCodeRef code) {
    OSStatus status = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
    if (status == errSecCSUnsigned) {
        return @"unsigned";
    }
    if (status != errSecSuccess) {
        return @"invalid signature";
    }

    SecRequirementRef appleReq = NULL;
    status = SecRequirementCreateWithString(
        CFSTR("anchor apple"),
        kSecCSDefaultFlags,
        &appleReq
    );
    if (status == errSecSuccess) {
        status = SecCodeCheckValidity(code, kSecCSDefaultFlags, appleReq);
        CFRelease(appleReq);
        if (status == errSecSuccess) {
            return @"Apple";
        }
    }

    CFDictionaryRef infoRef = NULL;
    status = SecCodeCopySigningInformation(
        (SecStaticCodeRef)code,
        kSecCSSigningInformation,
        &infoRef
    );
    if (status != errSecSuccess || !infoRef) {
        return @"signed";
    }
    NSDictionary *info = (__bridge_transfer NSDictionary *)infoRef;

    uint32_t flags = [info[(__bridge id)kSecCodeInfoFlags] unsignedIntValue];
    if (flags & kSecCodeSignatureAdhoc) {
        return @"ad-hoc signed";
    }

    NSArray *certs = info[(__bridge id)kSecCodeInfoCertificates];
    if (certs.count > 0) {
        SecCertificateRef leaf = (__bridge SecCertificateRef)certs[0];
        NSString *summary =
            (__bridge_transfer NSString *)SecCertificateCopySubjectSummary(leaf);
        if (summary) {
            return summary;
        }
    }

    NSString *team = info[(__bridge id)kSecCodeInfoTeamIdentifier];
    if (team) {
        return [NSString stringWithFormat:@"team %@", team];
    }
    return @"signed";
}

char *pi_get_signer(int pid) {
    @autoreleasepool {
        NSDictionary *attrs = @{(__bridge id)kSecGuestAttributePid: @(pid)};
        SecCodeRef code = NULL;

        OSStatus status = SecCodeCopyGuestWithAttributes(
            NULL,
            (__bridge CFDictionaryRef)attrs,
            kSecCSDefaultFlags,
            &code
        );
        if (status != errSecSuccess || !code) {
            return NULL;
        }

        NSString *result = describeSigner(code);
        CFRelease(code);
        return strdup([result UTF8String]); // caller must free
    }
}
