//go:build darwin
// +build darwin

package darwin

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication -lbsm
#include "touchid.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

var (
	ErrAuthFailedOrCancelled = fmt.Errorf("authentication failed or cancelled")
	//nolint:staticcheck
	ErrTouchIdNotAvailable = fmt.Errorf("Touch ID is not available")
)

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
