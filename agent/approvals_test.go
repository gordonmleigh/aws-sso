package agent

import (
	"testing"
	"time"
)

func TestApprovals(t *testing.T) {
	now := time.Now()
	work := sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"}
	home := sessionKey{region: "eu-central-1", startUrl: "https://home.awsapps.com/start"}

	sessionLong := approvalKey{session: work, pid: 1, accountId: "111111111111", roleName: "RO"}
	timed := approvalKey{session: work, pid: 2, accountId: "111111111111", roleName: "RO"}
	otherSession := approvalKey{session: home, pid: 1, accountId: "111111111111", roleName: "RO"}

	a := newApprovals()
	a.remember(sessionLong, time.Time{})
	a.remember(timed, now.Add(15*time.Minute))
	a.remember(otherSession, time.Time{})

	if !a.isApproved(timed, now.Add(15*time.Minute-time.Second)) {
		t.Error("a timed approval should last until it expires")
	}
	if a.isApproved(timed, now.Add(15*time.Minute)) {
		t.Error("a timed approval should expire")
	}
	if !a.isApproved(sessionLong, now.Add(1000*time.Hour)) {
		t.Error("an approval for the session shouldn't expire by itself")
	}

	// a different role, or the same process under another session, isn't
	// approved by these
	otherRole := sessionLong
	otherRole.roleName = "Admin"
	if a.isApproved(otherRole, now) {
		t.Error("another role shouldn't be approved")
	}

	if count := a.forgetSession(work); count != 1 {
		t.Errorf("forgot %d approvals, want 1", count)
	}
	if a.isApproved(sessionLong, now) {
		t.Error("the session's approvals should be forgotten")
	}
	if !a.isApproved(otherSession, now) {
		t.Error("another session's approvals should be kept")
	}

	a.remember(sessionLong, time.Time{})
	a.remember(timed, now.Add(time.Hour))
	a.forgetPid(1)
	if a.isApproved(sessionLong, now) || a.isApproved(otherSession, now) {
		t.Error("the process's approvals should be forgotten")
	}
	if !a.isApproved(timed, now) {
		t.Error("another process's approvals should be kept")
	}
}
