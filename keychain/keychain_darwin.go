//go:build darwin
// +build darwin

package keychain

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication
#include "keychain.h"
#include <stdlib.h>
#include <Security/Security.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type KeychainError int

var (
	ErrAuthFailedOrCancelled = fmt.Errorf("authentication failed or cancelled")
	ErrSecItemNotFound       = KeychainError(C.errSecItemNotFound)
	//lint:ignore ST1005 Touch ID is supposed to be capitalized
	ErrTouchIdNotAvailable = fmt.Errorf("Touch ID is not available")
)

func (e KeychainError) Error() string {
	return fmt.Sprintf("platform error %s", describeStatus(int(e)))
}

func SetKeychainItem(service string, key string, value string) error {
	cservice := C.CString(service)
	ckey := C.CString(key)
	cval := C.CString(value)
	defer C.free(unsafe.Pointer(cservice))
	defer C.free(unsafe.Pointer(ckey))
	defer C.free(unsafe.Pointer(cval))

	status := C.kc_set_item(cservice, ckey, cval)
	if status != 0 {
		return KeychainError(status)
	}
	return nil
}

func GetKeychainItem(service string, key string) (string, error) {
	cservice := C.CString(service)
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(cservice))
	defer C.free(unsafe.Pointer(ckey))

	var cstr *C.char
	status := C.kc_get_item(cservice, ckey, &cstr)

	if status != 0 {
		return "", KeychainError(status)
	}
	defer C.free(unsafe.Pointer(cstr))

	return C.GoString(cstr), nil
}

func RequestUserAuthorization(reason string) error {
	creason := C.CString(reason)
	defer C.free(unsafe.Pointer(creason))

	status := C.kc_authenticate_user(creason)
	switch status {
	case 0:
		return nil
	case 1:
		return ErrAuthFailedOrCancelled
	case -1:
		return ErrTouchIdNotAvailable
	default:
		return fmt.Errorf("unknown auth result: %d", int(status))
	}
}

func GetParentProcessName() string {
	cstr := C.kc_parent_process_name()
	if cstr == nil {
		return "(unknown process)"
	}
	defer C.free(unsafe.Pointer(cstr))
	return C.GoString(cstr)
}

func describeStatus(status int) string {
	cmsg := C.kc_error_message(C.int(status))
	if cmsg == nil {
		return fmt.Sprintf("unknown (%d)", status)
	}
	defer C.free(unsafe.Pointer(cmsg))
	return C.GoString(cmsg)
}
