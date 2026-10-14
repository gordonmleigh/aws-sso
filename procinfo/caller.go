package procinfo

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gordonmleigh/aws-sso/darwin"
)

const (
	maxAncestors  = 8
	maxArgsLength = 150
)

var (
	ErrCallerChanged = errors.New("calling process changed during identification")
	ErrNoCaller      = errors.New("calling process has exited")
)

type Caller struct {
	Process *darwin.Process
	Signer  string
	// Ancestors of Process, nearest first, not including launchd.
	Ancestors []*darwin.Process
	// ParentSigner is the signer of Ancestors[0], if known.
	ParentSigner string
}

// IdentifyParent describes the parent of the process with the given pid.
func IdentifyParent(pid int) (*Caller, error) {
	child, err := darwin.GetProcess(pid)
	if err != nil {
		return nil, err
	}

	ppid := child.Ppid
	if ppid <= 1 {
		// the child has been reparented to launchd
		return nil, ErrNoCaller
	}

	parent, err := darwin.GetProcess(ppid)
	if err != nil {
		return nil, err
	}

	caller := &Caller{
		Process:   parent,
		Signer:    parent.Signer(),
		Ancestors: ancestors(parent.Ppid),
	}

	// make sure the pid wasn't reused while we were looking at it
	child, err = darwin.GetProcess(pid)
	if err != nil || child.Ppid != ppid {
		return nil, ErrCallerChanged
	}
	current, err := darwin.GetProcess(ppid)
	if err != nil || !current.SameAs(parent) {
		return nil, ErrCallerChanged
	}

	return caller, nil
}

// IdentifyProcess describes the process with the given pid itself.
func IdentifyProcess(pid int) (*Caller, error) {
	proc, err := darwin.GetProcess(pid)
	if err != nil {
		return nil, err
	}

	caller := &Caller{
		Process:   proc,
		Signer:    proc.Signer(),
		Ancestors: ancestors(proc.Ppid),
	}
	if len(caller.Ancestors) > 0 {
		caller.ParentSigner = caller.Ancestors[0].Signer()
	}

	// make sure the pid wasn't reused while we were looking at it
	current, err := darwin.GetProcess(pid)
	if err != nil || !current.SameAs(proc) {
		return nil, ErrCallerChanged
	}
	return caller, nil
}

// ancestors returns the process with the given pid and its ancestors, nearest
// first, stopping before launchd.
func ancestors(pid int) []*darwin.Process {
	var result []*darwin.Process
	for next := pid; next > 1 && len(result) < maxAncestors; {
		proc, err := darwin.GetProcess(next)
		if err != nil {
			break
		}
		result = append(result, proc)
		next = proc.Ppid
	}
	return result
}

// Describe returns a single-line summary suitable for an authorization prompt,
// e.g. `/usr/bin/python3 script.py [Apple] (via Terminal → login → zsh)`.
func (caller *Caller) Describe() string {
	var b strings.Builder

	b.WriteString(commandLine(caller.Process))
	fmt.Fprintf(&b, " [🔐 %s]", caller.Signer)
	writeVia(&b, caller.Ancestors)
	return b.String()
}

// DescribeMcpProxy returns a single-line summary of an MCP proxy for an
// endpoint, for an authorization prompt, e.g. `the MCP proxy for
// aws-mcp.us-east-1.api.aws, started by claude [🔐 Developer ID Application:
// …] (via Terminal → login → zsh)`. The proxy itself is aws-sso, so it's
// described by what started it rather than its command line.
func (caller *Caller) DescribeMcpProxy(endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "the MCP proxy for %s", endpoint)

	if len(caller.Ancestors) > 0 {
		fmt.Fprintf(
			&b,
			", started by %s [🔐 %s]",
			processName(caller.Ancestors[0]),
			caller.ParentSigner,
		)
		writeVia(&b, caller.Ancestors[1:])
	}
	return b.String()
}

// writeVia writes the names of ancestors, furthest first.
func writeVia(b *strings.Builder, ancestors []*darwin.Process) {
	if len(ancestors) == 0 {
		return
	}
	names := make([]string, 0, len(ancestors))
	for _, proc := range slices.Backward(ancestors) {
		names = append(names, processName(proc))
	}
	fmt.Fprintf(b, " (via %s)", strings.Join(names, " → "))
}

// commandLine uses the executable path rather than argv[0], because argv[0]
// can be set to anything by the process that started it.
func commandLine(proc *darwin.Process) string {
	path := proc.Path
	if path == "" {
		path = fmt.Sprintf("(unknown process %d)", proc.Pid)
	}
	if len(proc.Args) <= 1 {
		return path
	}

	args := make([]string, 0, len(proc.Args)-1)
	for _, arg := range proc.Args[1:] {
		args = append(args, quoteArg(arg))
	}

	argStr := strings.Join(args, " ")
	if runes := []rune(argStr); len(runes) > maxArgsLength {
		argStr = string(runes[:maxArgsLength]) + "…"
	}
	return path + " " + argStr
}

func processName(proc *darwin.Process) string {
	if proc.Path == "" {
		return strconv.Itoa(proc.Pid)
	}
	return filepath.Base(proc.Path)
}

func quoteArg(arg string) string {
	if arg == "" || strings.ContainsAny(arg, " \t\n\"'\\") {
		return strconv.Quote(arg)
	}
	return arg
}
