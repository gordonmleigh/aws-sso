package agent

import (
	"strings"
	"time"

	"github.com/gordonmleigh/aws-sso/darwin"
)

// approvalKey identifies an approval for an exact process instance running a
// particular program to get credentials for a particular SSO session, account
// and role.
type approvalKey struct {
	session   sessionKey
	pid       int
	startSec  uint64
	startUsec uint64
	path      string
	args      string
	accountId string
	roleName  string
}

func newApprovalKey(
	session sessionKey,
	proc *darwin.Process,
	accountId string,
	roleName string,
) approvalKey {
	return approvalKey{
		session:   session,
		pid:       proc.Pid,
		startSec:  proc.StartSec,
		startUsec: proc.StartUsec,
		path:      proc.Path,
		args:      strings.Join(proc.Args, "\x00"),
		accountId: accountId,
		roleName:  roleName,
	}
}

// approvals remembers what the user has approved. It isn't safe for concurrent
// use.
type approvals struct {
	// entries maps each approval to when it expires; the zero time means it
	// lasts until the SSO session ends
	entries map[approvalKey]time.Time
}

func newApprovals() *approvals {
	return &approvals{entries: map[approvalKey]time.Time{}}
}

func (a *approvals) isApproved(key approvalKey, now time.Time) bool {
	for k, expires := range a.entries {
		if !expires.IsZero() && !expires.After(now) {
			delete(a.entries, k)
		}
	}
	_, ok := a.entries[key]
	return ok
}

// remember approves key until expires, or until the SSO session ends if
// expires is zero.
func (a *approvals) remember(key approvalKey, expires time.Time) {
	a.entries[key] = expires
}

// forgetSession forgets the approvals for an SSO session, and returns how many
// there were.
func (a *approvals) forgetSession(session sessionKey) int {
	count := 0
	for key := range a.entries {
		if key.session == session {
			delete(a.entries, key)
			count++
		}
	}
	return count
}

// forgetPid forgets the approvals for a process.
func (a *approvals) forgetPid(pid int) {
	for key := range a.entries {
		if key.pid == pid {
			delete(a.entries, key)
		}
	}
}
