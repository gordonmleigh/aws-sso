package agent

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/gordonmleigh/aws-sso/darwin"
	"github.com/gordonmleigh/aws-sso/procinfo"
	"golang.org/x/sys/unix"
)

type Server struct {
	// Authorize asks the user to approve reason. Defaults to Touch ID.
	Authorize func(reason string) error
	// McpProxy returns the MCP host name if the args represent a call to the
	// mcp-proxy command.
	McpProxy func(args []string) (host string, ok bool)

	exe string
	kq  int

	// promptMu makes sure only one prompt is shown at a time
	promptMu sync.Mutex

	// logins makes sure only one session logs in at a time
	logins chan struct{}

	// handlers is the connections being handled
	handlers sync.WaitGroup

	mu        sync.Mutex
	approvals *approvals
	sessions  map[sessionKey]*session
	watched   map[int]bool
}

// Run serves requests on the socket that launchd created for this job.
func (srv *Server) Run(ctx context.Context) error {
	fds, err := darwin.ActivateSocket(socketName)
	if err != nil {
		return fmt.Errorf(
			"the agent must be started by launchd (run `aws-sso agent install`): %w",
			err,
		)
	}
	if len(fds) != 1 {
		return fmt.Errorf("expected 1 socket from launchd, got %d", len(fds))
	}

	file := os.NewFile(uintptr(fds[0]), "agent.sock")
	listener, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return err
	}

	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		listener.Close()
		return errors.New("launchd socket is not a unix socket")
	}
	return srv.Serve(ctx, unixListener)
}

// unixListener is the part of *net.UnixListener that Serve uses.
type unixListener interface {
	AcceptUnix() (*net.UnixConn, error)
	Close() error
}

const (
	minAcceptRetry = 5 * time.Millisecond
	maxAcceptRetry = time.Second
)

// Serve handles connections until ctx ends or the listener is closed, and then
// waits for the requests in progress to finish. When ctx ends, the requests in
// progress are cancelled. It always closes the listener before returning.
func (srv *Server) Serve(ctx context.Context, listener unixListener) error {
	defer listener.Close()

	if err := darwin.InitPeerChecks(); err != nil {
		return err
	}

	var err error
	if srv.exe, err = executablePath(); err != nil {
		return err
	}
	if srv.Authorize == nil {
		srv.Authorize = darwin.RequestUserAuthorization
	}
	if srv.McpProxy == nil {
		return errors.New("the agent needs to know how to recognise the MCP proxy")
	}
	if srv.kq, err = unix.Kqueue(); err != nil {
		return fmt.Errorf("kqueue: %w", err)
	}
	defer unix.Close(srv.kq)

	srv.approvals = newApprovals()
	srv.sessions = map[sessionKey]*session{}
	srv.logins = newLoginLock()
	srv.watched = map[int]bool{}

	go srv.watchExits()
	log.Printf("[DEBUG] agent listening (%s)\n", srv.exe)

	// stop accepting connections when ctx ends
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()

	// the tokens and approvals only exist in memory, so a failure to accept a
	// connection (e.g. running out of file descriptors) mustn't stop the
	// agent; only a closed listener does
	retry := time.Duration(0)
	for {
		conn, err := listener.AcceptUnix()
		if errors.Is(err, net.ErrClosed) {
			srv.handlers.Wait()
			return nil
		}
		if err != nil {
			retry = min(max(2*retry, minAcceptRetry), maxAcceptRetry)
			log.Printf("[WARN] failed to accept connection, retrying in %s: %v\n", retry, err)
			select {
			case <-time.After(retry):
			case <-ctx.Done():
			}
			continue
		}
		retry = 0

		srv.handlers.Go(func() { srv.handle(ctx, conn) })
	}
}

func (srv *Server) handle(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	// Reads and writes don't take a context, so close the connection to stop
	// them when the server stops. We don't allow any grace period here because
	// the connection is pending while waiting on user interaction.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		// without a deadline a stuck client could tie up the agent forever
		log.Printf("[WARN] dropping connection: failed to set deadline: %v\n", err)
		return
	}

	enc := jsontext.NewEncoder(conn)
	dec := jsontext.NewDecoder(conn)

	// the client created its end of the socket, so we can check it straight away
	peerPid, sameCode, err := darwin.CheckPeer(conn)
	if err != nil {
		log.Printf("[WARN] rejecting connection: %v\n", err)
		// don't care if it fails, client is being told to go away anyway
		_ = json.MarshalEncode(
			enc,
			hello{Version: protocolVersion, Error: "failed to verify client"},
		)
		waitForClose(conn)
		return
	}
	if !sameCode {
		if peer, err := darwin.GetProcess(peerPid); err == nil && isExecutable(peer.Path, srv.exe) {
			// the binary has been replaced since the agent started, and the
			// agent is only replaced when the user reinstalls it
			log.Printf(
				"[WARN] rejecting connection from a different build, run `aws-sso agent install`\n",
			)
			// don't care if it fails, client is being told to go away anyway
			_ = json.MarshalEncode(enc, hello{Version: protocolVersion, Outdated: true})
			waitForClose(conn)
			return
		}
		log.Printf(
			"[WARN] rejecting connection from process %d: not the installed aws-sso binary\n",
			peerPid,
		)
		// don't care if it fails, client is being told to go away anyway
		_ = json.MarshalEncode(enc,
			hello{Version: protocolVersion, Error: "client is not the installed aws-sso binary"},
		)
		waitForClose(conn)
		return
	}

	if err := json.MarshalEncode(enc, hello{Version: protocolVersion}); err != nil {
		return
	}

	var req request
	if err := json.UnmarshalDecode(dec, &req); err != nil {
		log.Printf("[WARN] failed to read request: %v\n", err)
		if isProtocolError(err) {
			// don't care if it fails, client is being told to go away anyway
			_ = json.MarshalEncode(enc, response{Outdated: true})
		}
		return
	}
	if req.Version != protocolVersion {
		log.Printf(
			"[WARN] rejecting request with protocol version %d (agent has %d), run `aws-sso agent install`\n",
			req.Version,
			protocolVersion,
		)
		// don't care if it fails, client is being told to go away anyway
		_ = json.MarshalEncode(enc, response{Outdated: true})
		return
	}

	if req.Region == "" || req.StartUrl == "" {
		// don't care if it fails, client is being told to go away anyway
		_ = json.MarshalEncode(enc, response{Error: "region and start URL are required"})
		return
	}

	// stop waiting for logins etc. if the client goes away; it doesn't send
	// anything else, so a read only returns when it closes the connection
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		cancel()
	}()

	resp, err := srv.dispatch(ctx, conn, peerPid, &req)
	if err != nil {
		log.Printf("[WARN] %s failed: %v\n", req.Op, err)
		resp = &response{Error: err.Error()}
	}
	if err := json.MarshalEncode(enc, resp); err != nil {
		log.Printf("[WARN] failed to send %s response: %v\n", req.Op, err)
	}
}

// requestCaller is the process a request is from, as far as approvals are
// concerned. It's added to the request's context so that a login can be
// approved by whatever caused it.
type requestCaller struct {
	caller      *procinfo.Caller
	description string
	approvalTtl *textDuration
}

type requestCallerKey struct{}

func (srv *Server) dispatch(
	ctx context.Context,
	conn *net.UnixConn,
	clientPid int,
	req *request,
) (*response, error) {
	caller, description, err := srv.identifyCaller(clientPid)
	if err != nil {
		return nil, fmt.Errorf("failed to identify calling process: %w", err)
	}
	// the client was looked up by pid, which another process could have been
	// given if the client exited in the meantime; if it's still running, the
	// pid was still its own
	if running, err := darwin.PeerRunning(conn); err != nil || !running {
		return nil, fmt.Errorf(
			"failed to identify calling process: %w",
			errors.Join(procinfo.ErrCallerChanged, err),
		)
	}
	rc := &requestCaller{caller: caller, description: description, approvalTtl: req.ApprovalTtl}
	ctx = context.WithValue(ctx, requestCallerKey{}, rc)

	sess := srv.getSession(sessionKey{region: req.Region, startUrl: req.StartUrl})

	switch req.Op {
	// listing gives nothing that grants access, so it isn't approved; logging
	// in for it is, in beforeLogin
	case opListAccounts:
		accounts, err := sess.listAccounts(ctx)
		return &response{Accounts: accounts}, err

	case opListRoles:
		account, err := sess.findAccount(ctx, req.AccountId)
		if err != nil {
			return nil, err
		}
		roles, err := sess.listRoles(ctx, account.AccountId)
		return &response{Roles: roles}, err

	case opGetRoleCredentials:
		// log in first: a login forgets the approvals for the old session, so
		// one mustn't happen between checking the approval and using it
		if err := sess.ensureAuthorized(ctx); err != nil {
			return nil, err
		}
		account, err := sess.findAccount(ctx, req.AccountId)
		if err != nil {
			return nil, err
		}
		if err := sess.checkRole(ctx, account.AccountId, req.RoleName); err != nil {
			return nil, err
		}

		key := newApprovalKey(
			sess.key,
			caller.Process,
			account.AccountId,
			req.RoleName,
		)
		reason := fmt.Sprintf(
			"give role credentials for account %s (%s), role \"%s\" to %s",
			account.AccountName,
			account.AccountId,
			req.RoleName,
			description,
		)
		if err := srv.approve(ctx, key, req.ApprovalTtl, reason); err != nil {
			return nil, err
		}

		creds, err := sess.roleCredentials(ctx, account.AccountId, req.RoleName)
		return &response{
			Credentials: creds,
			AccountId:   account.AccountId,
			AccountName: account.AccountName,
		}, err

	default:
		return nil, fmt.Errorf("unknown operation %q", req.Op)
	}
}

func (srv *Server) getSession(key sessionKey) *session {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	sess := srv.sessions[key]
	if sess == nil {
		sess = newSession(key, srv.logins)
		sess.beforeLogin = func(ctx context.Context, newClient bool) error {
			return srv.beforeLogin(ctx, key, newClient)
		}
		srv.sessions[key] = sess
	}
	return sess
}

// waitForClose keeps the connection open until the client closes it, so that
// the client can still verify who it's talking to after reading our reply.
func waitForClose(conn *net.UnixConn) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.Copy(io.Discard, conn)
}

// approve asks the user to approve reason, unless key has already been
// approved, and remembers the approval according to ttl.
func (srv *Server) approve(
	ctx context.Context,
	key approvalKey,
	ttl *textDuration,
	reason string,
) error {
	if srv.isApproved(key) {
		log.Printf("[INFO] approved (cached): %s\n", reason)
		return nil
	}

	srv.promptMu.Lock()
	defer srv.promptMu.Unlock()

	// another request may have been approved while we were waiting
	if srv.isApproved(key) {
		log.Printf("[INFO] approved (cached): %s\n", reason)
		return nil
	}

	if err := srv.authorize(ctx, reason); err != nil {
		return err
	}
	srv.rememberFor(key, ttl)
	return nil
}

// beforeLogin is called with the session locked, just before logging in
// through the browser, which ends the old session.
//
// The caller of the request that needs the login must always be approved
// first, so that no process can open login pages in the browser or end the
// session without the user knowing which one did it. If newClient is set, AWS
// will also show its consent page, which is then only legitimate straight
// after this prompt. The login gives the caller nothing that grants access
// without a further approval.
func (srv *Server) beforeLogin(ctx context.Context, key sessionKey, newClient bool) error {
	rc, _ := ctx.Value(requestCallerKey{}).(*requestCaller)
	if rc == nil {
		return errors.New("logging in needs a request to approve it")
	}

	srv.promptMu.Lock()
	defer srv.promptMu.Unlock()

	reason := fmt.Sprintf("log in to AWS SSO at %s for %s", key.startUrl, rc.description)
	if newClient {
		reason += ", which AWS will ask you to allow"
	}
	if err := srv.authorize(ctx, reason); err != nil {
		return err
	}

	// the old session is over
	srv.forgetSession(key)
	return nil
}

// authorize shows the prompt. srv.promptMu must be held.
func (srv *Server) authorize(ctx context.Context, reason string) error {
	// the client may have gone while waiting for another prompt, and then
	// nobody would be waiting for this one
	if err := ctx.Err(); err != nil {
		log.Printf("[DEBUG] not asking, the request was cancelled: %s\n", reason)
		return err
	}
	if err := srv.Authorize(reason); err != nil {
		log.Printf("[INFO] denied: %s: %v\n", reason, err)
		return fmt.Errorf("failed to get user consent: %w", err)
	}
	log.Printf("[INFO] approved: %s\n", reason)
	return nil
}

// rememberFor remembers an approval: until the session ends if ttl is nil,
// for ttl if it's positive, and not at all if it's zero.
func (srv *Server) rememberFor(key approvalKey, ttl *textDuration) {
	switch {
	case ttl == nil:
		srv.remember(key, time.Time{})
	case *ttl > 0:
		srv.remember(key, time.Now().Add(time.Duration(*ttl)))
	}
}

// identifyCaller works out which process a request is from, and describes it
// for the approval prompt. That's the MCP proxy itself if the client is one;
// otherwise it's the parent of the client.
//
// The client has already been checked as the same code as the agent, so its
// arguments decide what it does exactly as they did when it started.
func (srv *Server) identifyCaller(clientPid int) (*procinfo.Caller, string, error) {
	client, err := procinfo.IdentifyProcess(clientPid)
	if err != nil {
		return nil, "", err
	}

	host, isProxy := srv.McpProxy(client.Process.Args)
	if !isProxy {
		caller, err := procinfo.IdentifyParent(clientPid)
		if err != nil {
			return nil, "", err
		}
		return caller, caller.Describe(), nil
	}
	return client, client.DescribeMcpProxy(host), nil
}

func (srv *Server) isApproved(key approvalKey) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.approvals.isApproved(key, time.Now())
}

// forgetSession forgets the approvals for an SSO session, because it's ended.
func (srv *Server) forgetSession(key sessionKey) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if count := srv.approvals.forgetSession(key); count > 0 {
		log.Printf("[DEBUG] logging in to %s, %d approvals forgotten\n", key.startUrl, count)
	}
}

func (srv *Server) remember(key approvalKey, expires time.Time) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if !srv.watched[key.pid] {
		// forget approvals as soon as the process exits or runs something else
		var ev unix.Kevent_t
		unix.SetKevent(&ev, key.pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ONESHOT)
		ev.Fflags = unix.NOTE_EXIT | unix.NOTE_EXEC

		if _, err := unix.Kevent(srv.kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
			// most likely the process has already exited
			log.Printf("[DEBUG] not remembering approval for %d: %v\n", key.pid, err)
			return
		}
		srv.watched[key.pid] = true
	}
	srv.approvals.remember(key, expires)
}

func (srv *Server) watchExits() {
	events := make([]unix.Kevent_t, 16)
	for {
		n, err := unix.Kevent(srv.kq, nil, events, nil)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			// the kqueue is closed when the server stops
			return
		}

		srv.mu.Lock()
		for _, ev := range events[:n] {
			pid := int(ev.Ident)
			delete(srv.watched, pid)
			srv.approvals.forgetPid(pid)
			log.Printf("[DEBUG] process %d exited or exec'd, approvals forgotten\n", pid)
		}
		srv.mu.Unlock()
	}
}
