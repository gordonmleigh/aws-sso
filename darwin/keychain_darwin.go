//go:build darwin
// +build darwin

package darwin

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security
#include "keychain.h"
#include <stdlib.h>
#include <Security/Security.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// KeychainError is an OSStatus from the keychain.
type KeychainError int

var ErrKeychainItemNotFound = KeychainError(C.errSecItemNotFound)

func (e KeychainError) Error() string {
	cmsg := C.kc_error_message(C.int(e))
	if cmsg == nil {
		return fmt.Sprintf("keychain error %d", int(e))
	}
	defer C.free(unsafe.Pointer(cmsg))
	return fmt.Sprintf("keychain error %d: %s", int(e), C.GoString(cmsg))
}

// SetKeychainItem stores value as a generic password, replacing any existing
// one.
func SetKeychainItem(service string, key string, value string) error {
	cservice := C.CString(service)
	ckey := C.CString(key)
	cvalue := C.CString(value)
	defer C.free(unsafe.Pointer(cservice))
	defer C.free(unsafe.Pointer(ckey))
	defer C.free(unsafe.Pointer(cvalue))

	if status := C.kc_set_item(cservice, ckey, cvalue); status != 0 {
		return KeychainError(status)
	}
	return nil
}

// GetKeychainItem returns a generic password, or ErrKeychainItemNotFound.
func GetKeychainItem(service string, key string) (string, error) {
	cservice := C.CString(service)
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(cservice))
	defer C.free(unsafe.Pointer(ckey))

	var cvalue *C.char
	if status := C.kc_get_item(cservice, ckey, &cvalue); status != 0 {
		return "", KeychainError(status)
	}
	defer C.free(unsafe.Pointer(cvalue))
	return C.GoString(cvalue), nil
}

// DeleteKeychainItem removes a generic password, if there is one.
func DeleteKeychainItem(service string, key string) error {
	cservice := C.CString(service)
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(cservice))
	defer C.free(unsafe.Pointer(ckey))

	if status := C.kc_delete_item(cservice, ckey); status != 0 {
		return KeychainError(status)
	}
	return nil
}
