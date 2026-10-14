//go:build darwin
// +build darwin

package darwin

/*
#include "procinfo.h"
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"fmt"
	"unsafe"
)

type Process struct {
	Pid  int
	Ppid int
	// StartSec and StartUsec identify the process along with Pid, because pids
	// can be reused once a process exits.
	StartSec  uint64
	StartUsec uint64
	Path      string
	Args      []string
}

func GetProcess(pid int) (*Process, error) {
	var info C.pi_bsdinfo
	if C.pi_get_bsdinfo(C.int(pid), &info) != 0 {
		return nil, fmt.Errorf("failed to get info for process %d", pid)
	}

	proc := &Process{
		Pid:       pid,
		Ppid:      int(info.ppid),
		StartSec:  uint64(info.start_sec),
		StartUsec: uint64(info.start_usec),
	}

	if cpath := C.pi_get_path(C.int(pid)); cpath != nil {
		proc.Path = C.GoString(cpath)
		C.free(unsafe.Pointer(cpath))
	}

	var argsLen C.int
	if cargs := C.pi_get_args(C.int(pid), &argsLen); cargs != nil {
		raw := C.GoBytes(unsafe.Pointer(cargs), argsLen)
		C.free(unsafe.Pointer(cargs))

		for arg := range bytes.SplitSeq(bytes.TrimSuffix(raw, []byte{0}), []byte{0}) {
			proc.Args = append(proc.Args, string(arg))
		}
	}

	return proc, nil
}

// SameAs reports whether other refers to the same process instance.
func (proc *Process) SameAs(other *Process) bool {
	return proc.Pid == other.Pid &&
		proc.StartSec == other.StartSec &&
		proc.StartUsec == other.StartUsec
}

// Signer describes the code signing identity of the running process, e.g.
// "Apple", "Developer ID Application: Example Ltd (TEAMID)" or "unsigned".
func (proc *Process) Signer() string {
	csigner := C.pi_get_signer(C.int(proc.Pid))
	if csigner == nil {
		return "unknown signer"
	}
	defer C.free(unsafe.Pointer(csigner))
	return C.GoString(csigner)
}
