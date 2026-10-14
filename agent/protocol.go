package agent

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gordonmleigh/aws-sso/sso"
)

// Label is the launchd job label. It's a variable so that test builds can use
// a separate agent via -ldflags "-X github.com/gordonmleigh/aws-sso/agent.Label=...".
var Label = "io.propulsionworks.aws-sso.agent"

const (
	protocolVersion = 4
	socketName      = "Listeners"
	// maximum length of a unix socket path, including the terminator
	maxSocketPath = 104
	// long enough to log in through the browser and then approve with Touch ID
	requestTimeout = 10 * time.Minute
)

const (
	opListAccounts       = "listAccounts"
	opListRoles          = "listRoles"
	opGetRoleCredentials = "getRoleCredentials"
)

// hello is sent by the agent as soon as a client connects.
type hello struct {
	Version  int    `json:"version"`
	Outdated bool   `json:"outdated,omitzero"`
	Error    string `json:"error,omitempty"`
}

type request struct {
	Version  int    `json:"version"`
	Op       string `json:"op"`
	Region   string `json:"region"`
	StartUrl string `json:"startUrl"`
	// AccountId is an account ID or name.
	AccountId string `json:"accountId,omitempty"`
	RoleName  string `json:"roleName,omitempty"`
	// ApprovalTtl is how long the user's approval is remembered for the
	// calling process. Nil means until the SSO session ends, and zero means
	// the user is asked every time.
	ApprovalTtl *textDuration `json:"approvalTtl,omitzero"`
}

type response struct {
	Outdated    bool              `json:"outdated,omitzero"`
	Error       string            `json:"error,omitempty"`
	Accounts    []sso.AccountInfo `json:"accounts,omitempty"`
	Roles       []sso.RoleInfo    `json:"roles,omitempty"`
	Credentials *aws.Credentials  `json:"credentials,omitempty"`
	AccountId   string            `json:"accountId,omitempty"`
	AccountName string            `json:"accountName,omitempty"`
}

// isProtocolError reports whether err is from a message that was received
// but couldn't be understood, rather than from the connection.
func isProtocolError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	var syntaxErr *jsontext.SyntacticError
	var semanticErr *json.SemanticError
	return errors.As(err, &syntaxErr) || errors.As(err, &semanticErr)
}

// textDuration encodes a time.Duration as a string like "15m0s", because
// json/v2 has no default representation for durations (and the `format` tag
// isn't supported by the standard library yet).
type textDuration time.Duration

func (d textDuration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

func (d *textDuration) UnmarshalText(text []byte) error {
	value, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = textDuration(value)
	return nil
}

func SocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(home, "Library", "Application Support", Label, "agent.sock")
	if len(path) >= maxSocketPath {
		return "", fmt.Errorf("agent socket path is too long: %s", path)
	}
	return path, nil
}

func executablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// isExecutable reports whether path is the same file as exe.
func isExecutable(path string, exe string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && resolved == exe
}
