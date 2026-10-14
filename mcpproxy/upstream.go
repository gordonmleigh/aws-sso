package mcpproxy

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// how much of an error response body to include in errors
const maxErrorBody = 4096

var (
	errSessionExpired = errors.New("upstream session expired")
	errNoCredentials  = errors.New("no unexpired credentials to sign with")
)

// statusError is an unsuccessful HTTP response from the upstream server.
type statusError struct {
	status int
	body   string
}

func (e *statusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("upstream server returned HTTP %d", e.status)
	}
	return fmt.Sprintf("upstream server returned HTTP %d: %s", e.status, e.body)
}

// credentialsError is a failure to get credentials to sign a request.
type credentialsError struct {
	err error
}

func (e *credentialsError) Error() string {
	return fmt.Sprintf("failed to get AWS credentials: %v", e.err)
}

func (e *credentialsError) Unwrap() error {
	return e.err
}

// upstream is an MCP session with the remote server over Streamable HTTP,
// signed with one profile's credentials. The session is set up on first use.
type upstream struct {
	endpoint string
	http     *http.Client
	signer   *signer
	creds    aws.CredentialsProvider
	// meta is added to the _meta of every request
	meta map[string]string
	// onConnect is called each time a new session is set up
	onConnect func(u *upstream, init *initializeResult)

	// connectMu is held while setting up a session, so only one is set up
	connectMu sync.Mutex

	mu              sync.Mutex
	initParams      jsontext.Value
	connected       bool
	sessionId       string
	protocolVersion string
	initResult      *initializeResult
	// lastCreds is what the last request was signed with
	lastCreds aws.Credentials
}

// setInitParams sets the initialize params to send when connecting, which are
// the client's own.
func (u *upstream) setInitParams(params jsontext.Value) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.initParams = params
}

func (u *upstream) isConnected() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.connected
}

// connect sets up a session if there isn't one already.
func (u *upstream) connect(ctx context.Context) error {
	u.connectMu.Lock()
	defer u.connectMu.Unlock()

	u.mu.Lock()
	connected := u.connected
	params := u.initParams
	u.mu.Unlock()
	if connected {
		return nil
	}

	req := &message{JSONRPC: "2.0", ID: nextId(), Method: "initialize", Params: params}
	resp, header, err := u.post(ctx, req, nil)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("upstream initialize failed: %w", resp.Error)
	}

	var init initializeResult
	if err := json.Unmarshal(resp.Result, &init); err != nil {
		return fmt.Errorf("invalid initialize result from upstream: %w", err)
	}

	u.mu.Lock()
	u.sessionId = header.Get("Mcp-Session-Id")
	u.protocolVersion = init.ProtocolVersion
	u.mu.Unlock()

	if _, _, err := u.post(ctx, newNotification("notifications/initialized"), nil); err != nil {
		u.reset()
		return err
	}

	u.mu.Lock()
	u.connected = true
	u.initResult = &init
	u.mu.Unlock()
	log.Printf("[DEBUG] connected to %s (protocol %s)\n", u.endpoint, init.ProtocolVersion)

	if u.onConnect != nil {
		u.onConnect(u, &init)
	}
	return nil
}

// initialized returns what the server said when the session was set up.
func (u *upstream) initialized() *initializeResult {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.initResult
}

// reset forgets the session, so the next call sets up a new one.
func (u *upstream) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.connected = false
	u.sessionId = ""
	u.protocolVersion = ""
}

// call sends a request, setting up a session first if needed, and returns the
// response. Any notifications the server sends while handling the request are
// passed to onMessage.
func (u *upstream) call(
	ctx context.Context,
	msg *message,
	onMessage func(*message),
) (*message, error) {
	for attempt := 0; ; attempt++ {
		if err := u.connect(ctx); err != nil {
			return nil, err
		}

		resp, _, err := u.post(ctx, msg, onMessage)
		if errors.Is(err, errSessionExpired) && attempt == 0 {
			log.Printf("[DEBUG] upstream session expired, reconnecting\n")
			u.reset()
			continue
		}

		var statusErr *statusError
		var credsErr *credentialsError
		if err != nil && ctx.Err() == nil &&
			!errors.As(err, &statusErr) && !errors.As(err, &credsErr) {
			// the connection failed, so start again next time
			u.reset()
		}
		return resp, err
	}
}

// notify sends a notification, but only if there's a session already.
func (u *upstream) notify(ctx context.Context, msg *message) {
	if !u.isConnected() {
		return
	}
	if _, _, err := u.post(ctx, msg, nil); err != nil {
		log.Printf("[DEBUG] failed to send %s upstream: %v\n", msg.Method, err)
	}
}

// list gets every page of a list method's results.
func (u *upstream) list(ctx context.Context, lm *listMethod) ([]jsontext.Value, error) {
	var items []jsontext.Value
	cursor := ""

	for {
		params := map[string]string{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		req, err := newRequest(lm.method, params)
		if err != nil {
			return nil, err
		}
		resp, err := u.call(ctx, req, nil)
		if err != nil {
			return nil, err
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("upstream %s failed: %w", lm.method, resp.Error)
		}

		var page map[string]jsontext.Value
		if err := json.Unmarshal(resp.Result, &page); err != nil {
			return nil, fmt.Errorf("invalid %s result from upstream: %w", lm.method, err)
		}
		var pageItems []jsontext.Value
		if raw, ok := page[lm.field]; ok {
			if err := json.Unmarshal(raw, &pageItems); err != nil {
				return nil, fmt.Errorf("invalid %s result from upstream: %w", lm.method, err)
			}
		}
		items = append(items, pageItems...)

		var next string
		if raw, ok := page["nextCursor"]; ok {
			if err := json.Unmarshal(raw, &next); err != nil {
				return nil, fmt.Errorf("invalid %s result from upstream: %w", lm.method, err)
			}
		}
		if next == "" {
			return items, nil
		}
		cursor = next
	}
}

// lists gets everything the server lists, for each capability it advertises.
func (u *upstream) lists(
	ctx context.Context,
	init *initializeResult,
) (map[string][]jsontext.Value, error) {
	lists := map[string][]jsontext.Value{}
	for i := range listMethods {
		lm := &listMethods[i]
		if !init.hasCapability(lm.capability) {
			continue
		}
		items, err := u.list(ctx, lm)
		var rpcErr *rpcError
		if errors.As(err, &rpcErr) {
			// the server said no, rather than failing, so treat it as empty
			log.Printf("[DEBUG] treating %s as empty: %v\n", lm.method, err)
			items, err = nil, nil
		}
		if err != nil {
			return nil, err
		}
		lists[lm.method] = items
	}
	return lists, nil
}

// post sends one message. For a request, it returns the matching response.
func (u *upstream) post(
	ctx context.Context,
	msg *message,
	onMessage func(*message),
) (*message, http.Header, error) {
	out := *msg
	if msg.isRequest() {
		params, err := injectMeta(msg.Params, u.meta)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid params: %w", err)
		}
		out.Params = params
	}
	body, err := json.Marshal(&out)
	if err != nil {
		return nil, nil, err
	}

	creds, err := u.credentials(ctx, msg)
	if err != nil {
		return nil, nil, err
	}

	u.mu.Lock()
	sessionId := u.sessionId
	protocolVersion := u.protocolVersion
	u.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("User-Agent", "aws-sso-mcp-proxy")
	if sessionId != "" {
		req.Header.Set("Mcp-Session-Id", sessionId)
	}
	if protocolVersion != "" {
		req.Header.Set("Mcp-Protocol-Version", protocolVersion)
	}
	if err := u.signer.sign(ctx, req, body, creds); err != nil {
		return nil, nil, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := u.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound && sessionId != "" {
		return nil, nil, errSessionExpired
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return nil, nil, &statusError{
			status: resp.StatusCode,
			body:   strings.TrimSpace(string(errBody)),
		}
	}

	if !msg.isRequest() {
		return nil, resp.Header, nil
	}

	result, err := u.readResponse(ctx, resp, msg.ID, onMessage)
	return result, resp.Header, err
}

// credentials returns the credentials to sign msg with. Requests get them from
// creds, which can ask the user to approve new ones. Notifications and replies
// are best effort, so they're never worth asking the user about: they use the
// last credentials, and fail with errNoCredentials if those have expired.
func (u *upstream) credentials(ctx context.Context, msg *message) (aws.Credentials, error) {
	if !msg.isRequest() {
		u.mu.Lock()
		creds := u.lastCreds
		u.mu.Unlock()

		if !creds.HasKeys() || creds.Expired() {
			return aws.Credentials{}, errNoCredentials
		}
		return creds, nil
	}

	creds, err := u.creds.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, &credentialsError{err: err}
	}
	u.mu.Lock()
	u.lastCreds = creds
	u.mu.Unlock()
	return creds, nil
}

func (u *upstream) readResponse(
	ctx context.Context,
	resp *http.Response,
	id jsontext.Value,
	onMessage func(*message),
) (*message, error) {
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))

	switch mediaType {
	case "application/json":
		var result message
		if err := json.UnmarshalRead(resp.Body, &result); err != nil {
			return nil, fmt.Errorf("invalid response from upstream: %w", err)
		}
		return &result, nil

	case "text/event-stream":
		var result *message
		err := readEvents(resp.Body, func(data []byte) error {
			var m message
			if err := json.Unmarshal(data, &m); err != nil {
				return fmt.Errorf("invalid message from upstream: %w", err)
			}

			switch {
			case m.isRequest():
				// we don't pass on requests from the server, so say so rather
				// than leave it waiting
				reply := newError(m.ID, codeMethodNotFound, "not supported by aws-sso mcp-proxy")
				if _, _, err := u.post(ctx, reply, nil); err != nil {
					log.Printf("[DEBUG] failed to reject %s from upstream: %v\n", m.Method, err)
				}
			case m.isNotification():
				if onMessage != nil {
					onMessage(&m)
				}
			case sameJson(m.ID, id):
				result = &m
				return errStopEvents
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if result == nil {
			return nil, errors.New("upstream closed the stream without responding")
		}
		return result, nil

	default:
		return nil, fmt.Errorf("unexpected content type from upstream: %q", mediaType)
	}
}

// close ends the session, if there is one and the credentials are still valid
// (so that closing never asks for approval).
func (u *upstream) close(ctx context.Context) {
	u.mu.Lock()
	sessionId := u.sessionId
	creds := u.lastCreds
	u.mu.Unlock()

	if sessionId == "" || !creds.HasKeys() || creds.Expired() {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Mcp-Session-Id", sessionId)
	req.Header.Set("User-Agent", "aws-sso-mcp-proxy")
	if err := u.signer.sign(ctx, req, nil, creds); err != nil {
		return
	}

	resp, err := u.http.Do(req)
	if err != nil {
		log.Printf("[DEBUG] failed to close upstream session: %v\n", err)
		return
	}
	resp.Body.Close()
}
