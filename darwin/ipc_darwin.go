//go:build darwin
// +build darwin

package darwin

/*
#include "ipc.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// ActivateSocket returns the file descriptors for the named socket from the
// launchd job's Sockets dictionary.
func ActivateSocket(name string) ([]int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	var cfds *C.int
	var count C.size_t

	if errno := C.ipc_activate_socket(cname, &cfds, &count); errno != 0 {
		return nil, fmt.Errorf("launch_activate_socket: %w", syscall.Errno(errno))
	}
	defer C.free(unsafe.Pointer(cfds))

	fds := make([]int, 0, int(count))
	for _, fd := range unsafe.Slice(cfds, int(count)) {
		fds = append(fds, int(fd))
	}
	return fds, nil
}

// InitPeerChecks records the code signing requirement of this process, so
// that CheckPeer still works correctly if the binary is replaced on disk. It
// should be called as early as possible.
func InitPeerChecks() error {
	if C.ipc_init_self_requirement() != 0 {
		return errors.New(
			"failed to get own code requirement (the binary may have changed since it started)",
		)
	}
	return nil
}

// CheckPeer returns the pid of the process at the other end of conn, and
// whether it is running the same code as this process. The peer must have
// written to (or created) its end of the connection before this is called.
func CheckPeer(conn *net.UnixConn) (pid int, sameCode bool, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, false, err
	}

	var cpid C.int
	var result C.int
	if err = raw.Control(func(fd uintptr) {
		result = C.ipc_check_peer(C.int(fd), &cpid)
	}); err != nil {
		return 0, false, err
	}

	switch result {
	case C.IPC_PEER_SAME_CODE:
		return int(cpid), true, nil
	case C.IPC_PEER_DIFFERENT_CODE:
		return int(cpid), false, nil
	case C.IPC_ERR_PEER_TOKEN:
		return 0, false, errors.New("failed to get peer audit token")
	case C.IPC_ERR_PEER_CODE:
		return int(cpid), false, errors.New("failed to get peer code object")
	case C.IPC_ERR_SELF_REQUIREMENT:
		return int(cpid), false, errors.New("failed to get own code requirement")
	default:
		return 0, false, fmt.Errorf("unknown peer check result: %d", int(result))
	}
}

// PeerRunning reports whether the process that CheckPeer identified at the
// other end of conn is still running. Its pid can only have been reused by
// another process if it isn't, so a pid that was looked up before this
// returned true still referred to the peer.
func PeerRunning(conn *net.UnixConn) (bool, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false, err
	}

	var result, errno C.int
	if err = raw.Control(func(fd uintptr) {
		result = C.ipc_peer_running(C.int(fd), &errno)
	}); err != nil {
		return false, err
	}

	switch result {
	case 1:
		return true, nil
	case 0:
		return false, nil
	case C.IPC_ERR_PEER_TOKEN:
		return false, fmt.Errorf("failed to get peer audit token: %w", syscall.Errno(errno))
	default:
		return false, fmt.Errorf("unknown peer check result: %d", int(result))
	}
}
