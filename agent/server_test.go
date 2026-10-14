package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gordonmleigh/aws-sso/darwin"
	"github.com/gordonmleigh/aws-sso/procinfo"
	"golang.org/x/sys/unix"
)

// testServer is a server with its approval bookkeeping set up, and a fake
// prompt.
type testServer struct {
	*Server
	prompts []string
	deny    bool
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	kq, err := unix.Kqueue()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(kq) })

	ts := &testServer{}
	ts.Server = &Server{
		Authorize: func(reason string) error {
			ts.prompts = append(ts.prompts, reason)
			if ts.deny {
				return errors.New("denied")
			}
			return nil
		},
		kq:        kq,
		approvals: newApprovals(),
		sessions:  map[sessionKey]*session{},
		logins:    newLoginLock(),
		watched:   map[int]bool{},
	}
	return ts
}

// testCaller is a request from this process, which is alive to be watched.
func testCaller(t *testing.T, ttl *textDuration) (context.Context, *requestCaller) {
	t.Helper()
	proc, err := darwin.GetProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	rc := &requestCaller{
		caller:      &procinfo.Caller{Process: proc},
		description: "the test",
		approvalTtl: ttl,
	}
	return context.WithValue(context.Background(), requestCallerKey{}, rc), rc
}

func TestApproveLogin(t *testing.T) {
	srv := newTestServer(t)
	ctx, rc := testCaller(t, nil)
	work := sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"}
	home := sessionKey{region: "eu-central-1", startUrl: "https://home.awsapps.com/start"}

	oldCreds := newApprovalKey(work, rc.caller.Process, "111111111111", "RO")
	otherSession := newApprovalKey(home, rc.caller.Process, "111111111111", "RO")
	srv.remember(oldCreds, time.Time{})
	srv.remember(otherSession, time.Time{})

	// denying the login leaves everything as it was
	srv.deny = true
	if err := srv.beforeLogin(ctx, work, true); err == nil {
		t.Fatal("a denied login should fail")
	}
	if !srv.isApproved(oldCreds) {
		t.Error("a denied login shouldn't forget approvals")
	}

	srv.deny = false
	if err := srv.beforeLogin(ctx, work, true); err != nil {
		t.Fatal(err)
	}
	if len(srv.prompts) != 2 || srv.prompts[1] !=
		"log in to AWS SSO at https://work.awsapps.com/start for the test, which AWS will ask you to allow" {
		t.Errorf("prompts = %q", srv.prompts)
	}
	if srv.isApproved(oldCreds) {
		t.Error("logging in should forget the session's approvals")
	}
	if !srv.isApproved(otherSession) {
		t.Error("logging in shouldn't forget another session's approvals")
	}

	// logging in doesn't approve credentials
	if err := srv.approve(ctx, oldCreds, nil, "creds"); err != nil {
		t.Fatal(err)
	}
	if len(srv.prompts) != 3 {
		t.Errorf("credentials after logging in should prompt: %q", srv.prompts)
	}

	if err := srv.beforeLogin(context.Background(), work, true); err == nil ||
		!strings.Contains(err.Error(), "needs a request") {
		t.Errorf("a login without a request: got %v", err)
	}
	if len(srv.prompts) != 3 {
		t.Errorf("a login without a request shouldn't prompt: %q", srv.prompts)
	}
}

func TestLoginWithConsentedClient(t *testing.T) {
	srv := newTestServer(t)
	ctx, rc := testCaller(t, nil)
	work := sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"}

	oldCreds := newApprovalKey(work, rc.caller.Process, "111111111111", "RO")
	srv.remember(oldCreds, time.Time{})

	// it still needs approving, so that no process can open the browser
	// unnoticed, but there's no consent page to mention
	if err := srv.beforeLogin(context.Background(), work, false); err == nil {
		t.Error("a login without a request should fail")
	}
	if err := srv.beforeLogin(ctx, work, false); err != nil {
		t.Fatal(err)
	}
	if len(srv.prompts) != 1 ||
		srv.prompts[0] != "log in to AWS SSO at https://work.awsapps.com/start for the test" {
		t.Errorf("prompts = %q", srv.prompts)
	}
	if srv.isApproved(oldCreds) {
		t.Error("logging in should forget the session's approvals")
	}
}

func TestApproveTtl(t *testing.T) {
	work := sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"}
	zero := textDuration(0)
	hour := textDuration(time.Hour)

	tests := map[string]struct {
		ttl        *textDuration
		remembered bool
	}{
		"session":     {nil, true},
		"always ask":  {&zero, false},
		"for an hour": {&hour, true},
	}
	for name, tt := range tests {
		srv := newTestServer(t)
		ctx, rc := testCaller(t, tt.ttl)
		key := newApprovalKey(work, rc.caller.Process, "111111111111", "RO")

		if err := srv.approve(ctx, key, tt.ttl, "creds"); err != nil {
			t.Fatal(err)
		}
		if err := srv.approve(ctx, key, tt.ttl, "creds"); err != nil {
			t.Fatal(err)
		}

		wantPrompts := 1
		if !tt.remembered {
			wantPrompts = 2
		}
		if len(srv.prompts) != wantPrompts {
			t.Errorf("%s: got %d prompts, want %d", name, len(srv.prompts), wantPrompts)
		}
	}
}

func TestNoPromptAfterCancel(t *testing.T) {
	srv := newTestServer(t)
	ctx, rc := testCaller(t, nil)
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	work := sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"}
	key := newApprovalKey(work, rc.caller.Process, "111111111111", "RO")

	if err := srv.approve(ctx, key, nil, "creds"); !errors.Is(err, context.Canceled) {
		t.Errorf("approve: got %v, want context.Canceled", err)
	}
	if err := srv.beforeLogin(ctx, work, true); !errors.Is(err, context.Canceled) {
		t.Errorf("beforeLogin: got %v, want context.Canceled", err)
	}
	if len(srv.prompts) != 0 {
		t.Errorf("a cancelled request shouldn't prompt: %q", srv.prompts)
	}
	if srv.isApproved(key) {
		t.Error("a cancelled request shouldn't be approved")
	}
}

// flakyListener fails to accept a few times, and then is closed.
type flakyListener struct {
	failures int
	accepts  int
}

func (l *flakyListener) AcceptUnix() (*net.UnixConn, error) {
	l.accepts++
	if l.accepts <= l.failures {
		return nil, &net.OpError{Op: "accept", Net: "unix", Err: syscall.EMFILE}
	}
	return nil, net.ErrClosed
}

func (l *flakyListener) Close() error {
	return nil
}

func TestServeRetriesFailedAccepts(t *testing.T) {
	listener := &flakyListener{failures: 2}
	srv := &Server{
		Authorize: func(string) error { return errors.New("no prompts in tests") },
		McpProxy:  func([]string) (string, bool) { return "", false },
	}

	if err := srv.Serve(context.Background(), listener); err != nil {
		t.Errorf("Serve returned %v, want nil once the listener is closed", err)
	}
	if listener.accepts != 3 {
		t.Errorf("accepted %d times, want 3 (2 failures, then closed)", listener.accepts)
	}
}
