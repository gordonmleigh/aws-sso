package agent

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gordonmleigh/aws-sso/darwin"
	"github.com/gordonmleigh/aws-sso/sso"
)

var (
	ErrNotInstalled = errors.New(
		"the aws-sso agent isn't available, run `aws-sso agent install` to set it up",
	)

	// errOutdated means the agent is a different build or speaks a different
	// protocol. The agent is only replaced when it's reinstalled.
	errOutdated = errors.New(
		"the aws-sso agent doesn't match this version of aws-sso, run `aws-sso agent install` to update it",
	)
)

// Client talks to the agent, which holds the SSO session for Region and
// StartUrl. The agent logs in through the browser when it needs to.
type Client struct {
	Region   string
	StartUrl string
	// ApprovalTtl is how long the user's approval for the calling process (the
	// parent of this process, or this process if it's the MCP proxy) to list
	// accounts and roles or get credentials is remembered. Nil means until the SSO session ends, and zero means the
	// user is asked every time.
	ApprovalTtl *time.Duration
}

func (c *Client) ListAccounts(ctx context.Context) ([]sso.AccountInfo, error) {
	resp, err := c.call(ctx, request{Op: opListAccounts})
	if err != nil {
		return nil, err
	}
	return resp.Accounts, nil
}

// ListRoles lists the roles in an account, which can be an ID or a name.
func (c *Client) ListRoles(ctx context.Context, account string) ([]sso.RoleInfo, error) {
	resp, err := c.call(ctx, request{Op: opListRoles, AccountId: account})
	if err != nil {
		return nil, err
	}
	return resp.Roles, nil
}

// RoleCredentials are credentials for a role, and the account they're for.
type RoleCredentials struct {
	Credentials aws.Credentials
	AccountId   string
	AccountName string
}

// GetRoleCredentials gets credentials for the calling process, once the user
// has approved it. The account can be an ID or a name.
func (c *Client) GetRoleCredentials(
	ctx context.Context,
	account string,
	roleName string,
) (*RoleCredentials, error) {
	resp, err := c.call(ctx, request{
		Op:        opGetRoleCredentials,
		AccountId: account,
		RoleName:  roleName,
	})
	if err != nil {
		return nil, err
	}
	if resp.Credentials == nil {
		return nil, errors.New("agent returned no credentials")
	}
	return &RoleCredentials{
		Credentials: *resp.Credentials,
		AccountId:   resp.AccountId,
		AccountName: resp.AccountName,
	}, nil
}

func (c *Client) call(ctx context.Context, req request) (*response, error) {
	req.Version = protocolVersion
	req.Region = c.Region
	req.StartUrl = c.StartUrl

	if c.ApprovalTtl != nil {
		ttl := textDuration(*c.ApprovalTtl)
		req.ApprovalTtl = &ttl
	}

	return call(ctx, &req)
}

func call(ctx context.Context, req *request) (*response, error) {
	if err := darwin.InitPeerChecks(); err != nil {
		return nil, err
	}

	path, err := SocketPath()
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	c, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, ErrNotInstalled
		}
		return nil, fmt.Errorf("failed to connect to agent: %w", err)
	}
	conn := c.(*net.UnixConn)
	defer conn.Close()

	// reads don't take a context, so close the connection to stop waiting (for
	// a login or approval) if ctx is cancelled; the agent sees that and stops
	// too
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	deadline := time.Now().Add(requestTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set agent connection deadline: %w", err)
	}

	enc := jsontext.NewEncoder(conn)
	dec := jsontext.NewDecoder(conn)

	var h hello
	if err := json.UnmarshalDecode(dec, &h); err != nil {
		return nil, readError(err)
	}

	// the agent has now written to its end of the socket, so we can check
	// it's really the agent and not something else listening on the path
	if err := verifyAgent(conn); err != nil {
		return nil, err
	}

	if h.Outdated || h.Version != protocolVersion {
		return nil, errOutdated
	}
	if h.Error != "" {
		return nil, fmt.Errorf("agent: %s", h.Error)
	}

	if err := json.MarshalEncode(enc, req); err != nil {
		return nil, fmt.Errorf("failed to send request to agent: %w", err)
	}

	var resp response
	if err := json.UnmarshalDecode(dec, &resp); err != nil {
		return nil, readError(err)
	}
	if resp.Outdated {
		return nil, errOutdated
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("agent: %s", resp.Error)
	}
	return &resp, nil
}

// readError describes a failure to read a message from the agent. A message
// that can't be understood means the agent speaks a different protocol.
func readError(err error) error {
	if isProtocolError(err) {
		return fmt.Errorf("%w (invalid message from agent: %v)", errOutdated, err)
	}
	return fmt.Errorf("failed to read from agent: %w", err)
}

func verifyAgent(conn *net.UnixConn) error {
	pid, sameCode, err := darwin.CheckPeer(conn)
	if err != nil {
		return fmt.Errorf("failed to verify agent: %w", err)
	}
	if sameCode {
		return nil
	}

	exe, err := executablePath()
	if err != nil {
		return err
	}
	peer, err := darwin.GetProcess(pid)
	if err != nil {
		return fmt.Errorf(
			"the agent socket is served by an unexpected process (%d), not this aws-sso binary",
			pid,
		)
	}
	if isExecutable(peer.Path, exe) {
		// the agent is running an older build of this binary
		return errOutdated
	}
	return fmt.Errorf(
		"the agent socket is served by an unexpected process (%d, %s), not this aws-sso binary",
		pid,
		peer.Path,
	)
}
