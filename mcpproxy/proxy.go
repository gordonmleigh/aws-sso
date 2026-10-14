// Package mcpproxy is a stdio MCP server that passes messages on to a remote
// MCP server over Streamable HTTP, signed with SigV4 using credentials from the
// agent.
//
// It answers initialize and tools/list from a cache, so that no credentials
// are needed (and the user isn't asked to approve anything) until a tool is
// actually called.
package mcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gordonmleigh/aws-sso/agent"
)

const (
	// used when there's no client to say which version it wants (-refresh)
	latestProtocolVersion = "2025-06-18"
	// how long to wait for upstream sessions to close on exit
	closeTimeout = 2 * time.Second
	// get new credentials this long before the old ones expire
	credentialsExpiryWindow = time.Minute
)

// Options configure the proxy.
type Options struct {
	// Endpoint is the URL of the remote MCP server.
	Endpoint string
	// Profiles that tool calls can be signed with. The first is the default.
	Profiles []Profile
	// Metadata is added to the _meta of every request.
	Metadata map[string]string
	// Region is the AWS_REGION for profiles that don't have their own.
	Region string
	// DefaultRegion is used if neither the profile nor Region give a region.
	DefaultRegion string
	// Service and SigningRegion override what's derived from the endpoint.
	Service       string
	SigningRegion string
	// CachePath overrides where the handshake is cached.
	CachePath string
	// Agent gets the credentials.
	Agent *agent.Client

	// for tests
	httpClient     *http.Client
	newCredentials func(Profile) aws.CredentialsProvider
}

type profile struct {
	Profile
	// region is the AWS_REGION sent with this profile's requests
	region string
	up     *upstream
}

// inFlight is a request from the client that hasn't been answered yet.
type inFlight struct {
	cancel context.CancelFunc
	up     *upstream
}

type Proxy struct {
	endpoint  string
	cachePath string
	profiles  []*profile
	byName    map[string]*profile

	outMu sync.Mutex
	out   io.Writer

	// ctx is for background work started while serving
	ctx context.Context
	wg  sync.WaitGroup

	mu             sync.Mutex
	handshake      *handshake
	inFlight       map[string]*inFlight
	refreshStarted bool
}

func New(opts Options) (*Proxy, error) {
	endpoint, err := url.Parse(opts.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return nil, fmt.Errorf("the endpoint must be an https:// URL: %s", opts.Endpoint)
	}
	if len(opts.Profiles) == 0 {
		return nil, errors.New("at least one profile is required")
	}
	if opts.Region != "" && opts.Metadata["AWS_REGION"] != "" {
		return nil, errors.New("give the region with -region or -metadata AWS_REGION=…, not both")
	}

	service, signingRegion := serviceAndRegion(endpoint.Hostname())
	if opts.Service != "" {
		service = opts.Service
	}
	if opts.SigningRegion != "" {
		signingRegion = opts.SigningRegion
	}
	if signingRegion == "" {
		return nil, fmt.Errorf(
			"can't tell the signing region from %s, use -signing-region",
			endpoint.Hostname(),
		)
	}

	p := &Proxy{
		endpoint:  opts.Endpoint,
		cachePath: opts.CachePath,
		byName:    map[string]*profile{},
		ctx:       context.Background(),
		inFlight:  map[string]*inFlight{},
	}
	if p.cachePath == "" {
		if p.cachePath, err = defaultCachePath(opts.Endpoint); err != nil {
			return nil, err
		}
	}

	httpClient := opts.httpClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	newCredentials := opts.newCredentials
	if newCredentials == nil {
		if opts.Agent == nil {
			return nil, errors.New("an agent client is required")
		}
		newCredentials = func(prof Profile) aws.CredentialsProvider {
			return &agentCredentials{agent: opts.Agent, account: prof.Account, role: prof.Role}
		}
	}

	sign := newSigner(service, signingRegion)
	defaultRegion := firstNonEmpty(opts.Region, opts.Metadata["AWS_REGION"], opts.DefaultRegion)

	for _, prof := range opts.Profiles {
		if prof.Name == "" {
			return nil, fmt.Errorf("profile %s/%s has no name", prof.Account, prof.Role)
		}
		if p.byName[prof.Name] != nil {
			return nil, fmt.Errorf("there's more than one profile called %q", prof.Name)
		}

		region := firstNonEmpty(prof.Region, defaultRegion)
		meta := map[string]string{}
		for key, value := range opts.Metadata {
			meta[key] = value
		}
		if region != "" {
			meta["AWS_REGION"] = region
		}

		creds := aws.NewCredentialsCache(
			newCredentials(prof),
			func(o *aws.CredentialsCacheOptions) { o.ExpiryWindow = credentialsExpiryWindow },
		)

		entry := &profile{
			Profile: prof,
			region:  region,
			up: &upstream{
				endpoint:  opts.Endpoint,
				http:      httpClient,
				signer:    sign,
				creds:     creds,
				meta:      meta,
				onConnect: p.onConnect,
			},
		}
		p.profiles = append(p.profiles, entry)
		p.byName[prof.Name] = entry
	}

	h, err := loadHandshake(p.cachePath, p.endpoint)
	if err != nil {
		log.Printf("[WARN] ignoring the cached tool list: %v\n", err)
	}
	p.handshake = h
	return p, nil
}

// CachePath is where the handshake with the upstream server is cached.
func (p *Proxy) CachePath() string {
	return p.cachePath
}

// Refresh connects to the upstream server with the default profile, and
// caches what it says. It returns the number of tools.
func (p *Proxy) Refresh(ctx context.Context) (int, error) {
	params, err := json.Marshal(map[string]any{
		"protocolVersion": latestProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "aws-sso", "version": "1"},
	})
	if err != nil {
		return 0, err
	}
	p.profiles[0].up.setInitParams(params)

	h, err := p.fetchHandshake(ctx)
	p.closeAll()
	if err != nil {
		return 0, err
	}
	if err := saveHandshake(p.cachePath, h); err != nil {
		return 0, err
	}
	return len(h.Lists["tools/list"]), nil
}

// Serve handles messages from in until it's closed, writing replies to out.
func (p *Proxy) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p.out = out
	p.ctx = ctx

	// read in the background, so that cancelling ctx (e.g. on SIGTERM) stops
	// serving even though a read from in can't be interrupted
	type read struct {
		line []byte
		err  error
	}
	reads := make(chan read)
	go func() {
		reader := bufio.NewReader(in)
		for {
			line, err := reader.ReadBytes('\n')
			select {
			case reads <- read{line, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			p.stop(cancel)
			return nil

		case r := <-reads:
			if line := bytes.TrimSpace(r.line); len(line) > 0 {
				p.handleLine(ctx, line)
			}
			if r.err != nil {
				// the client has gone, so nobody's waiting for anything else
				p.stop(cancel)
				if errors.Is(r.err, io.EOF) {
					return nil
				}
				return r.err
			}
		}
	}
}

// stop cancels anything in progress, waits a little for it to finish, and
// ends the upstream sessions.
func (p *Proxy) stop(cancel context.CancelFunc) {
	cancel()

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(closeTimeout):
		log.Printf("[WARN] gave up waiting for requests to finish\n")
	}

	p.closeAll()
}

func (p *Proxy) handleLine(ctx context.Context, line []byte) {
	if line[0] == '[' {
		p.send(newError(nil, codeInvalidRequest, "batches are not supported"))
		return
	}

	var msg message
	if err := json.Unmarshal(line, &msg); err != nil {
		p.send(newError(nil, codeParseError, err.Error()))
		return
	}
	msg.ID = compactId(msg.ID)

	switch {
	case msg.isNotification():
		p.handleNotification(ctx, &msg)

	case msg.Method == "initialize":
		// nothing else can happen until this is done, so handle it in order
		p.send(p.initialize(ctx, &msg))

	case msg.isRequest():
		reqCtx, cancel := context.WithCancel(ctx)
		key := msg.idKey()

		p.mu.Lock()
		p.inFlight[key] = &inFlight{cancel: cancel}
		p.mu.Unlock()

		p.wg.Go(func() {
			defer func() {
				cancel()
				p.mu.Lock()
				delete(p.inFlight, key)
				p.mu.Unlock()
			}()
			p.send(p.handleRequest(reqCtx, &msg))
		})

	default:
		// a response, but we never send the client any requests
		log.Printf("[DEBUG] ignoring unexpected response from client\n")
	}
}

func (p *Proxy) handleNotification(ctx context.Context, msg *message) {
	switch msg.Method {
	case "notifications/initialized":
		// each upstream session gets its own when it's set up

	case "notifications/cancelled":
		var params struct {
			RequestId jsontext.Value `json:"requestId"`
		}
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return
		}

		// forward sets request.up once it knows which upstream the request went
		// to, so read it while the lock is held
		p.mu.Lock()
		var cancel context.CancelFunc
		var up *upstream
		if request := p.inFlight[string(compactId(params.RequestId))]; request != nil {
			cancel, up = request.cancel, request.up
		}
		p.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		if up != nil {
			p.wg.Go(func() {
				notifyCtx, cancel := context.WithTimeout(context.Background(), closeTimeout)
				defer cancel()
				up.notify(notifyCtx, msg)
			})
		}

	default:
		p.wg.Go(func() { p.profiles[0].up.notify(ctx, msg) })
	}
}

func (p *Proxy) handleRequest(ctx context.Context, msg *message) *message {
	switch msg.Method {
	case "ping":
		return newResult(msg.ID, map[string]any{})
	case "tools/list", "prompts/list", "resources/list", "resources/templates/list":
		return p.listFromCache(msg, findListMethod(msg.Method))
	case "tools/call":
		return p.callTool(ctx, msg)
	default:
		return p.forward(ctx, p.profiles[0], msg)
	}
}

func (p *Proxy) initialize(ctx context.Context, msg *message) *message {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return newError(msg.ID, codeInvalidParams, err.Error())
	}

	upstreamParams := withClientCapabilities(msg.Params)

	p.mu.Lock()
	h := p.handshake
	p.mu.Unlock()

	if h == nil {
		log.Printf(
			"[WARN] nothing cached for %s, connecting now (`aws-sso mcp-proxy -refresh` caches it ahead of time)\n",
			p.endpoint,
		)
		p.profiles[0].up.setInitParams(upstreamParams)

		var err error
		if h, err = p.fetchHandshake(ctx); err != nil {
			return newError(
				msg.ID,
				codeInternalError,
				fmt.Sprintf("failed to connect to %s: %v", p.endpoint, err),
			)
		}
		if err := saveHandshake(p.cachePath, h); err != nil {
			log.Printf("[WARN] failed to cache the server's lists: %v\n", err)
		}
	}

	// the cached version is what the server agreed to before, so it supports
	// it; older versions are probably supported too
	version := h.ProtocolVersion
	if params.ProtocolVersion != "" && params.ProtocolVersion < version {
		version = params.ProtocolVersion
	}
	replay := withProtocolVersion(upstreamParams, version)
	for _, prof := range p.profiles {
		prof.up.setInitParams(replay)
	}

	result := map[string]any{
		"protocolVersion": version,
		"capabilities":    orEmptyObject(h.Capabilities),
		"serverInfo":      orEmptyObject(h.ServerInfo),
	}
	if h.Instructions != "" {
		result["instructions"] = h.Instructions
	}
	return newResult(msg.ID, result)
}

// fetchHandshake connects with the default profile and gets the tools.
func (p *Proxy) fetchHandshake(ctx context.Context) (*handshake, error) {
	p.mu.Lock()
	// it's about to be fresh, so there's no need to refresh it once connected
	p.refreshStarted = true
	p.mu.Unlock()

	up := p.profiles[0].up
	if err := up.connect(ctx); err != nil {
		return nil, err
	}
	init := up.initialized()
	lists, err := up.lists(ctx, init)
	if err != nil {
		return nil, err
	}

	h := newHandshake(p.endpoint, init, lists)
	p.mu.Lock()
	p.handshake = h
	p.mu.Unlock()
	return h, nil
}

// onConnect refreshes the cache the first time any upstream connects, since
// we have credentials by then anyway.
func (p *Proxy) onConnect(up *upstream, init *initializeResult) {
	p.mu.Lock()
	started := p.refreshStarted
	p.refreshStarted = true
	p.mu.Unlock()

	if !started {
		p.wg.Go(func() { p.refresh(p.ctx, up, init) })
	}
}

func (p *Proxy) refresh(ctx context.Context, up *upstream, init *initializeResult) {
	lists, err := up.lists(ctx, init)
	if err != nil {
		log.Printf("[DEBUG] failed to refresh the cache: %v\n", err)
		return
	}
	h := newHandshake(p.endpoint, init, lists)

	p.mu.Lock()
	old := p.handshake
	p.handshake = h
	p.mu.Unlock()

	if old != nil && old.sameAs(h) {
		return
	}
	log.Printf("[DEBUG] cached lists for %s have changed\n", p.endpoint)

	if err := saveHandshake(p.cachePath, h); err != nil {
		log.Printf("[WARN] failed to cache the server's lists: %v\n", err)
	}
	if old == nil {
		return
	}

	// tell the client about each list that changed, if the server said it
	// would, and only once for each notification
	sent := map[string]bool{}
	for _, lm := range listMethods {
		if !sent[lm.changed] && !old.sameList(h, lm.method) && old.listChanged(lm.capability) {
			p.send(newNotification(lm.changed))
			sent[lm.changed] = true
		}
	}
}

// listFromCache answers a list request from the cache, so that it doesn't
// need credentials. All the pages are returned at once.
func (p *Proxy) listFromCache(msg *message, lm *listMethod) *message {
	p.mu.Lock()
	h := p.handshake
	p.mu.Unlock()

	if h == nil {
		return newError(msg.ID, codeInternalError, "not initialized")
	}

	items := h.Lists[lm.method]
	if items == nil {
		items = []jsontext.Value{}
	}
	if lm.method == "tools/list" {
		var err error
		if items, err = withProfileArg(items, p.profiles); err != nil {
			return newError(msg.ID, codeInternalError, err.Error())
		}
	}
	return newResult(msg.ID, map[string]any{lm.field: items})
}

func (p *Proxy) callTool(ctx context.Context, msg *message) *message {
	params, name, profileName, err := takeProfileArg(msg.Params)
	if err != nil {
		return newError(msg.ID, codeInvalidParams, err.Error())
	}

	prof := p.profiles[0]
	if profileName != "" {
		if prof = p.byName[profileName]; prof == nil {
			names := make([]string, 0, len(p.profiles))
			for _, known := range p.profiles {
				names = append(names, known.Name)
			}
			return newToolError(msg.ID, fmt.Sprintf(
				"unknown %s %q, expected one of: %s",
				profileArg,
				profileName,
				strings.Join(names, ", "),
			))
		}
	}
	log.Printf("[DEBUG] calling %s with profile %s\n", name, prof.Name)

	forwarded := *msg
	forwarded.Params = params
	return p.forward(ctx, prof, &forwarded)
}

// forward sends a request upstream with prof, and returns the reply for the
// client.
func (p *Proxy) forward(ctx context.Context, prof *profile, msg *message) *message {
	p.mu.Lock()
	if request := p.inFlight[msg.idKey()]; request != nil {
		request.up = prof.up
	}
	p.mu.Unlock()

	resp, err := prof.up.call(ctx, msg, p.send)
	if err != nil {
		text := fmt.Sprintf("aws-sso mcp-proxy (profile %s): %v", prof.Name, err)
		log.Printf("[WARN] %s failed: %s\n", msg.Method, text)

		if msg.Method == "tools/call" {
			// the model can see this, unlike a protocol error
			return newToolError(msg.ID, text)
		}
		return newError(msg.ID, codeInternalError, text)
	}

	resp.JSONRPC = "2.0"
	resp.ID = msg.ID
	return resp
}

// send writes a message to the client.
func (p *Proxy) send(msg *message) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[WARN] failed to encode message: %v\n", err)
		return
	}
	// messages are separated by newlines, so they mustn't contain any
	if err := (*jsontext.Value)(&data).Compact(); err != nil {
		log.Printf("[WARN] failed to encode message: %v\n", err)
		return
	}
	data = append(data, '\n')

	p.outMu.Lock()
	defer p.outMu.Unlock()
	if _, err := p.out.Write(data); err != nil {
		log.Printf("[WARN] failed to write message: %v\n", err)
	}
}

// closeAll ends any upstream sessions.
func (p *Proxy) closeAll() {
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, prof := range p.profiles {
		wg.Go(func() { prof.up.close(ctx) })
	}
	wg.Wait()
}

// clientCapabilities are the client capabilities passed on to the upstream
// server. The proxy rejects every request from the server, so it can't offer
// any of them yet; one is only listed once its requests are passed on to the
// client.
var clientCapabilities = []string{}

// withClientCapabilities keeps only the client capabilities in params that the
// proxy supports, so the upstream server doesn't rely on anything else.
func withClientCapabilities(params jsontext.Value) jsontext.Value {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(params, &fields); err != nil {
		return params
	}

	// anything that isn't an object has no capabilities to keep
	var caps map[string]jsontext.Value
	_ = json.Unmarshal(fields["capabilities"], &caps)

	kept := map[string]jsontext.Value{}
	for _, name := range clientCapabilities {
		if value, ok := caps[name]; ok {
			kept[name] = value
		}
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		return params
	}
	fields["capabilities"] = raw

	result, err := json.Marshal(fields)
	if err != nil {
		return params
	}
	return result
}

func withProtocolVersion(params jsontext.Value, version string) jsontext.Value {
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(params, &fields); err != nil {
		return params
	}
	raw, err := json.Marshal(version)
	if err != nil {
		return params
	}
	fields["protocolVersion"] = raw

	result, err := json.Marshal(fields)
	if err != nil {
		return params
	}
	return result
}

// compactId removes any whitespace from an id, so it can be used as a key.
func compactId(id jsontext.Value) jsontext.Value {
	if id == nil {
		return nil
	}
	id = bytes.Clone(id)
	_ = id.Compact()
	return id
}

func orEmptyObject(value jsontext.Value) jsontext.Value {
	if len(value) == 0 {
		return jsontext.Value("{}")
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
