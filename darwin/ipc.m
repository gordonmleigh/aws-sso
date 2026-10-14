#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <bsm/libbsm.h>
#import <errno.h>
#import <launch.h>
#import <sys/socket.h>
#import <sys/un.h>

#include "ipc.h"

int ipc_activate_socket(const char *name, int **fds, size_t *count) {
    return launch_activate_socket(name, fds, count); // caller must free fds
}

// The designated requirement of our own code: for an ad-hoc signed binary
// this pins the exact build (cdhash), for a Developer ID signed binary it
// matches the signing identifier and team.
//
// The requirement is read from the binary on disk, which may have been
// replaced since we started, so it's computed once and checked against the
// running code.
static SecRequirementRef selfRequirement = NULL;

static SecRequirementRef getSelfRequirement(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        SecCodeRef selfCode = NULL;
        if (SecCodeCopySelf(kSecCSDefaultFlags, &selfCode) != errSecSuccess) {
            return;
        }

        SecRequirementRef requirement = NULL;
        OSStatus status = SecCodeCopyDesignatedRequirement(
            (SecStaticCodeRef)selfCode,
            kSecCSDefaultFlags,
            &requirement
        );
        if (status == errSecSuccess) {
            status = SecCodeCheckValidity(selfCode, kSecCSDefaultFlags, requirement);
            if (status == errSecSuccess) {
                selfRequirement = requirement;
            } else {
                CFRelease(requirement);
            }
        }
        CFRelease(selfCode);
    });
    return selfRequirement;
}

int ipc_init_self_requirement(void) {
    return getSelfRequirement() ? 0 : IPC_ERR_SELF_REQUIREMENT;
}

// Checks whether the process at the other end of a connected unix socket is
// running the same code as this process. The peer is identified by its audit
// token, so it can't be confused with another process that reuses its pid.
//
// The peer is the last process to use its end of the socket, so this must be
// called after the peer has sent something (or created the socket).
int ipc_check_peer(int fd, int *outPid) {
    @autoreleasepool {
        audit_token_t token;
        socklen_t len = sizeof(token);

        if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0) {
            return IPC_ERR_PEER_TOKEN;
        }
        *outPid = audit_token_to_pid(token);

        NSData *tokenData = [NSData dataWithBytes:&token length:sizeof(token)];
        NSDictionary *attrs = @{(__bridge id)kSecGuestAttributeAudit: tokenData};

        SecCodeRef peer = NULL;
        OSStatus status = SecCodeCopyGuestWithAttributes(
            NULL,
            (__bridge CFDictionaryRef)attrs,
            kSecCSDefaultFlags,
            &peer
        );
        if (status != errSecSuccess || !peer) {
            return IPC_ERR_PEER_CODE;
        }

        SecRequirementRef requirement = getSelfRequirement();
        if (!requirement) {
            CFRelease(peer);
            return IPC_ERR_SELF_REQUIREMENT;
        }

        status = SecCodeCheckValidity(peer, kSecCSDefaultFlags, requirement);
        CFRelease(peer);

        return status == errSecSuccess ? IPC_PEER_SAME_CODE : IPC_PEER_DIFFERENT_CODE;
    }
}

// Checks whether the process at the other end of a connected unix socket is
// still running. The peer is identified by its audit token, which includes the
// pid version, so this fails once that process has exited, even if another
// process now has its pid.
//
// The kernel won't give out the token once the peer has exited (EINVAL), even
// if a child it passed the socket to still has it open, and the socket is
// disconnected (ENOTCONN) once nothing has the other end open. Both mean the
// peer has gone. If the token is given out, it's checked against the running
// process too, in case the kernel ever stops refusing.
//
// Returns 1 if it's running, 0 if not, or IPC_ERR_PEER_TOKEN with the errno in
// outErrno.
int ipc_peer_running(int fd, int *outErrno) {
    @autoreleasepool {
        audit_token_t token;
        socklen_t len = sizeof(token);

        *outErrno = 0;
        if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0) {
            *outErrno = errno;
            return (errno == ENOTCONN || errno == EINVAL) ? 0 : IPC_ERR_PEER_TOKEN;
        }

        NSData *tokenData = [NSData dataWithBytes:&token length:sizeof(token)];
        NSDictionary *attrs = @{(__bridge id)kSecGuestAttributeAudit: tokenData};

        SecCodeRef peer = NULL;
        OSStatus status = SecCodeCopyGuestWithAttributes(
            NULL,
            (__bridge CFDictionaryRef)attrs,
            kSecCSDefaultFlags,
            &peer
        );
        if (peer) {
            CFRelease(peer);
        }
        return status == errSecSuccess ? 1 : 0;
    }
}
