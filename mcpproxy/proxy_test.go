package mcpproxy

import (
	"bufio"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// fakeCredentials counts how often credentials are asked for.
type fakeCredentials struct {
	calls *atomic.Int32
	fail  bool
}

func (c *fakeCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	c.calls.Add(1)
	if c.fail {
		return aws.Credentials{}, errors.New("user said no")
	}
	return aws.Credentials{
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET",
		CanExpire:       true,
		Expires:         time.Now().Add(time.Hour),
	}, nil
}

// fakeServer is a remote MCP server that records what it's sent.
type fakeServer struct {
	*httptest.Server

	mu       sync.Mutex
	requests []*message
	sessions int
	tools    string
}

func newFakeServer(t *testing.T) *fakeServer {
	s := &fakeServer{tools: `[{"name":"aws___run_script","inputSchema":{"type":"object"}}]`}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

func (s *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKID/") {
		http.Error(w, "not signed", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodDelete {
		return
	}

	var msg message
	if err := json.UnmarshalRead(r.Body, &msg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.requests = append(s.requests, &msg)
	tools := s.tools
	if msg.Method == "initialize" {
		s.sessions++
		w.Header().Set("Mcp-Session-Id", fmt.Sprintf("session-%d", s.sessions))
	}
	s.mu.Unlock()

	if msg.Method != "initialize" && r.Header.Get("Mcp-Session-Id") == "" {
		http.Error(w, "no session", http.StatusBadRequest)
		return
	}

	switch msg.Method {
	case "initialize":
		writeJson(w, msg.ID, `{
			"protocolVersion": "2025-06-18",
			"capabilities": {"tools": {"listChanged": true}, "prompts": {}, "resources": {}},
			"serverInfo": {"name": "fake", "version": "1"},
			"instructions": "be nice"
		}`)

	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)

	case "tools/list":
		writeJson(w, msg.ID, `{"tools":`+tools+`}`)

	case "prompts/list":
		writeJson(w, msg.ID, `{"prompts":[{"name":"a-prompt"}]}`)

	case "resources/list":
		writeJson(w, msg.ID, `{"resources":[{"uri":"x://a","name":"a-resource"}]}`)

	case "resources/templates/list":
		// the server says no, which should be cached as nothing
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no"}}`, msg.ID)

	case "tools/call":
		if strings.Contains(string(msg.Params), `"name":"slow"`) {
			// never answers, until the proxy gives up on it
			<-r.Context().Done()
			return
		}
		// reply over SSE, with a notification first and the result spread
		// over several lines
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(
			w,
			"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n\n",
		)
		fmt.Fprintf(
			w,
			"data: {\"jsonrpc\": \"2.0\",\ndata:  \"id\": %s,\ndata:  \"result\": {\"content\": [], \"echo\": %s}}\n\n",
			msg.ID,
			msg.Params,
		)

	default:
		writeJson(w, msg.ID, `{}`)
	}
}

func writeJson(w http.ResponseWriter, id jsontext.Value, result string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, id, result)
}

func (s *fakeServer) methods() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var methods []string
	for _, msg := range s.requests {
		methods = append(methods, msg.Method)
	}
	return methods
}

// testClient talks to a proxy like an MCP client would.
type testClient struct {
	t     *testing.T
	in    *io.PipeWriter
	lines chan string
	done  chan error
	creds map[string]*atomic.Int32
}

func startProxy(
	t *testing.T,
	server *fakeServer,
	opts Options,
	failing ...string,
) (*Proxy, *testClient) {
	t.Helper()

	client := &testClient{
		t:     t,
		lines: make(chan string, 100),
		done:  make(chan error, 1),
		creds: map[string]*atomic.Int32{},
	}
	for _, prof := range opts.Profiles {
		client.creds[prof.Name] = &atomic.Int32{}
	}

	opts.Endpoint = server.URL + "/mcp"
	opts.Service = "aws-mcp"
	opts.SigningRegion = "us-east-1"
	if opts.CachePath == "" {
		opts.CachePath = filepath.Join(t.TempDir(), "cache.json")
	}
	opts.httpClient = server.Client()
	opts.newCredentials = func(prof Profile) aws.CredentialsProvider {
		calls := client.creds[prof.Account+"/"+prof.Role]
		if calls == nil {
			calls = client.creds[prof.Name]
		}
		for _, name := range failing {
			if name == prof.Name {
				return &fakeCredentials{calls: calls, fail: true}
			}
		}
		return &fakeCredentials{calls: calls}
	}

	proxy, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}

	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	client.in = inWriter

	go func() {
		client.done <- proxy.Serve(context.Background(), inReader, outWriter)
		outWriter.Close()
	}()
	go func() {
		scanner := bufio.NewScanner(outReader)
		scanner.Buffer(nil, 1<<20)
		for scanner.Scan() {
			client.lines <- scanner.Text()
		}
		close(client.lines)
	}()

	t.Cleanup(func() {
		inWriter.Close()
		select {
		case err := <-client.done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("proxy didn't stop")
		}
	})
	return proxy, client
}

func (c *testClient) send(line string) {
	c.t.Helper()
	if _, err := io.WriteString(c.in, line+"\n"); err != nil {
		c.t.Fatal(err)
	}
}

func (c *testClient) receive() *message {
	c.t.Helper()
	select {
	case line, ok := <-c.lines:
		if !ok {
			c.t.Fatal("proxy closed its output")
		}
		var msg message
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			c.t.Fatalf("invalid message %q: %v", line, err)
		}
		return &msg
	case <-time.After(5 * time.Second):
		c.t.Fatal("timed out waiting for a message")
		return nil
	}
}

// call sends a request and returns its response, skipping notifications.
func (c *testClient) call(id int, method string, params string) (*message, []*message) {
	c.t.Helper()
	c.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, id, method, params))

	var notifications []*message
	for {
		msg := c.receive()
		if msg.isNotification() {
			notifications = append(notifications, msg)
			continue
		}
		if string(msg.ID) != fmt.Sprint(id) {
			c.t.Fatalf("got response for %s, want %d", msg.ID, id)
		}
		return msg, notifications
	}
}

func (c *testClient) initialize() *message {
	c.t.Helper()
	resp, _ := c.call(
		0,
		"initialize",
		`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}`,
	)
	c.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return resp
}

func writeCache(t *testing.T, server *fakeServer, path string, tools string) {
	t.Helper()
	var parsed []jsontext.Value
	if err := json.Unmarshal([]byte(tools), &parsed); err != nil {
		t.Fatal(err)
	}
	h := newHandshake(server.URL+"/mcp", &initializeResult{
		ProtocolVersion: "2025-06-18",
		Capabilities: jsontext.Value(
			`{"tools":{"listChanged":true},"prompts":{},"resources":{}}`,
		),
		ServerInfo: jsontext.Value(`{"name":"cached","version":"1"}`),
	}, map[string][]jsontext.Value{
		"tools/list":               parsed,
		"prompts/list":             {jsontext.Value(`{"name":"cached-prompt"}`)},
		"resources/list":           {},
		"resources/templates/list": {},
	})
	if err := saveHandshake(path, h); err != nil {
		t.Fatal(err)
	}
}

func toolText(t *testing.T, resp *message) string {
	t.Helper()
	var result struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	if !result.IsError || len(result.Content) != 1 {
		t.Fatalf("expected a tool error, got %s", resp.Result)
	}
	return result.Content[0].Text
}

func TestStartsWithoutCredentialsWhenCached(t *testing.T) {
	server := newFakeServer(t)
	cachePath := filepath.Join(t.TempDir(), "cache.json")
	writeCache(
		t,
		server,
		cachePath,
		`[{"name":"aws___run_script","inputSchema":{"type":"object"}}]`,
	)

	_, client := startProxy(t, server, Options{
		Profiles:  []Profile{{Name: "sb", Account: "Sandbox", Role: "RO"}},
		CachePath: cachePath,
	})

	init := client.initialize()
	var result initializeResult
	if err := json.Unmarshal(init.Result, &result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result.ServerInfo), "cached") {
		t.Errorf("initialize wasn't answered from the cache: %s", init.Result)
	}

	resp, _ := client.call(1, "tools/list", `{}`)
	if !strings.Contains(string(resp.Result), "aws___run_script") {
		t.Errorf("tools/list = %s", resp.Result)
	}
	resp, _ = client.call(2, "ping", `{}`)
	if resp.Error != nil {
		t.Errorf("ping failed: %v", resp.Error)
	}

	// clients list prompts and resources at startup too, if the server has them
	resp, _ = client.call(3, "prompts/list", `{}`)
	assertJson(t, resp.Result, `{"prompts":[{"name":"cached-prompt"}]}`)
	resp, _ = client.call(4, "resources/list", `{}`)
	assertJson(t, resp.Result, `{"resources":[]}`)
	resp, _ = client.call(5, "resources/templates/list", `{}`)
	assertJson(t, resp.Result, `{"resourceTemplates":[]}`)

	if methods := server.methods(); len(methods) != 0 {
		t.Errorf("upstream was sent %v", methods)
	}
	if calls := client.creds["sb"].Load(); calls != 0 {
		t.Errorf("credentials were fetched %d times", calls)
	}
}

func TestToolCallConnectsAndRefreshesCache(t *testing.T) {
	server := newFakeServer(t)
	cachePath := filepath.Join(t.TempDir(), "cache.json")
	writeCache(t, server, cachePath, `[{"name":"old"}]`)

	proxy, client := startProxy(t, server, Options{
		Profiles:  []Profile{{Name: "sb", Account: "Sandbox", Role: "RO"}},
		Region:    "eu-west-1",
		Metadata:  map[string]string{"OTHER": "x"},
		CachePath: cachePath,
	})
	client.initialize()

	resp, notifications := client.call(
		1,
		"tools/call",
		`{"name":"aws___run_script","arguments":{"code":"1"},"_meta":{"progressToken":7}}`,
	)
	if resp.Error != nil {
		t.Fatalf("tools/call failed: %v", resp.Error)
	}
	var result struct {
		Echo struct {
			Name string            `json:"name"`
			Meta map[string]any    `json:"_meta"`
			Args map[string]string `json:"arguments"`
		} `json:"echo"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.Echo.Meta["AWS_REGION"] != "eu-west-1" || result.Echo.Meta["OTHER"] != "x" ||
		result.Echo.Meta["progressToken"] != float64(7) {
		t.Errorf("upstream got _meta %v", result.Echo.Meta)
	}

	// the progress notification is passed on, and then the tool list changes
	// because the cache was out of date
	waitFor := func(method string) {
		t.Helper()
		for _, n := range notifications {
			if n.Method == method {
				return
			}
		}
		for {
			msg := client.receive()
			if msg.Method == method {
				return
			}
		}
	}
	waitFor("notifications/progress")
	waitFor("notifications/tools/list_changed")

	resp, _ = client.call(2, "tools/list", `{}`)
	if !strings.Contains(string(resp.Result), "aws___run_script") {
		t.Errorf("tools/list wasn't refreshed: %s", resp.Result)
	}

	cached, err := loadHandshake(proxy.CachePath(), proxy.endpoint)
	if err != nil || cached == nil || len(cached.Lists["tools/list"]) != 1 ||
		!strings.Contains(string(cached.Lists["tools/list"][0]), "aws___run_script") {
		t.Errorf("cache wasn't updated: %+v, %v", cached, err)
	}

	// the call and the refresh happen at the same time, so in any order
	methods := server.methods()
	slices.Sort(methods)
	want := []string{
		"initialize",
		"notifications/initialized",
		"prompts/list",
		"resources/list",
		"resources/templates/list",
		"tools/call",
		"tools/list",
	}
	if !slices.Equal(methods, want) {
		t.Errorf("upstream was sent %v, want %v", methods, want)
	}
	if calls := client.creds["sb"].Load(); calls == 0 {
		t.Error("credentials were never fetched")
	}
}

func TestConnectsAtStartWithoutCache(t *testing.T) {
	server := newFakeServer(t)
	proxy, client := startProxy(t, server, Options{
		Profiles: []Profile{{Name: "sb", Account: "Sandbox", Role: "RO"}},
	})

	init := client.initialize()
	if !strings.Contains(string(init.Result), `"fake"`) ||
		!strings.Contains(string(init.Result), "be nice") {
		t.Errorf("initialize = %s", init.Result)
	}

	cached, err := loadHandshake(proxy.CachePath(), proxy.endpoint)
	if err != nil || cached == nil || len(cached.Lists["tools/list"]) != 1 ||
		len(cached.Lists["prompts/list"]) != 1 || len(cached.Lists["resources/list"]) != 1 ||
		len(cached.Lists["resources/templates/list"]) != 0 {
		t.Errorf("cache wasn't written: %+v, %v", cached, err)
	}

	resp, _ := client.call(1, "tools/list", `{}`)
	if !strings.Contains(string(resp.Result), "aws___run_script") {
		t.Errorf("tools/list = %s", resp.Result)
	}
	if methods := strings.Join(
		server.methods(),
		",",
	); methods != "initialize,notifications/initialized,tools/list,prompts/list,resources/list,resources/templates/list" {
		t.Errorf("upstream was sent %s", methods)
	}
}

func TestOnlySupportedClientCapabilitiesUpstream(t *testing.T) {
	for _, cached := range []bool{false, true} {
		server := newFakeServer(t)
		cachePath := filepath.Join(t.TempDir(), "cache.json")
		if cached {
			writeCache(t, server, cachePath, server.tools)
		}
		_, client := startProxy(t, server, Options{
			Profiles:  []Profile{{Name: "sb", Account: "Sandbox", Role: "RO"}},
			CachePath: cachePath,
		})

		client.call(
			0,
			"initialize",
			`{"protocolVersion":"2025-06-18","capabilities":{"roots":{"listChanged":true},"sampling":{},"elicitation":{}},"clientInfo":{"name":"test","version":"1"}}`,
		)
		if cached {
			// the proxy only connects for a tool call
			client.call(1, "tools/call", `{"name":"aws___run_script","arguments":{}}`)
		}

		server.mu.Lock()
		init := server.requests[0]
		server.mu.Unlock()
		if init.Method != "initialize" {
			t.Fatalf("cached=%v: first upstream request was %s", cached, init.Method)
		}
		assertJson(
			t,
			init.Params,
			`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}`,
		)
	}
}

func TestSwitchesProfiles(t *testing.T) {
	server := newFakeServer(t)
	cachePath := filepath.Join(t.TempDir(), "cache.json")
	writeCache(
		t,
		server,
		cachePath,
		`[{"name":"aws___run_script","inputSchema":{"type":"object"}}]`,
	)

	_, client := startProxy(t, server, Options{
		Profiles: []Profile{
			{Name: "sb", Account: "Sandbox", Role: "RO"},
			{Name: "prod", Account: "Production", Role: "RO", Region: "us-east-1"},
			{Name: "denied", Account: "Other", Role: "RO"},
		},
		Region:    "eu-west-1",
		CachePath: cachePath,
	}, "denied")
	client.initialize()

	resp, _ := client.call(1, "tools/list", `{}`)
	if !strings.Contains(string(resp.Result), `"aws_profile"`) {
		t.Errorf("tools/list has no aws_profile: %s", resp.Result)
	}

	resp, _ = client.call(
		2,
		"tools/call",
		`{"name":"aws___run_script","arguments":{"aws_profile":"prod"}}`,
	)
	if !strings.Contains(string(resp.Result), `"AWS_REGION":"us-east-1"`) ||
		strings.Contains(string(resp.Result), "aws_profile") {
		t.Errorf("prod call = %s", resp.Result)
	}
	if client.creds["sb"].Load() != 0 || client.creds["prod"].Load() == 0 {
		t.Errorf(
			"credentials fetched: sb %d, prod %d",
			client.creds["sb"].Load(),
			client.creds["prod"].Load(),
		)
	}

	resp, _ = client.call(3, "tools/call", `{"name":"aws___run_script","arguments":{}}`)
	if !strings.Contains(string(resp.Result), `"AWS_REGION":"eu-west-1"`) {
		t.Errorf("default call = %s", resp.Result)
	}

	resp, _ = client.call(
		4,
		"tools/call",
		`{"name":"aws___run_script","arguments":{"aws_profile":"nope"}}`,
	)
	if text := toolText(t, resp); !strings.Contains(text, `unknown aws_profile "nope"`) {
		t.Errorf("unknown profile error = %q", text)
	}

	resp, _ = client.call(
		5,
		"tools/call",
		`{"name":"aws___run_script","arguments":{"aws_profile":"denied"}}`,
	)
	if text := toolText(t, resp); !strings.Contains(text, "user said no") {
		t.Errorf("denied error = %q", text)
	}

	server.mu.Lock()
	sessions := server.sessions
	server.mu.Unlock()
	if sessions != 2 {
		t.Errorf("got %d upstream sessions, want 2 (one each for prod and sb)", sessions)
	}
}

func TestOptions(t *testing.T) {
	base := func() Options {
		return Options{
			Endpoint:       "https://aws-mcp.us-east-1.api.aws/mcp",
			Profiles:       []Profile{{Name: "a", Account: "A", Role: "R"}},
			CachePath:      filepath.Join(t.TempDir(), "cache.json"),
			newCredentials: func(Profile) aws.CredentialsProvider { return &fakeCredentials{} },
		}
	}

	invalid := map[string]func(*Options){
		"http endpoint":      func(o *Options) { o.Endpoint = "http://aws-mcp.us-east-1.api.aws/mcp" },
		"no profiles":        func(o *Options) { o.Profiles = nil },
		"duplicate profiles": func(o *Options) { o.Profiles = append(o.Profiles, o.Profiles[0]) },
		"both regions": func(o *Options) {
			o.Region = "eu-west-1"
			o.Metadata = map[string]string{"AWS_REGION": "eu-west-2"}
		},
		"unknown signing region": func(o *Options) { o.Endpoint = "https://mcp.example.com/" },
	}
	for name, change := range invalid {
		opts := base()
		change(&opts)
		if _, err := New(opts); err == nil {
			t.Errorf("%s: should fail", name)
		}
	}

	regions := func(opts Options) []string {
		t.Helper()
		p, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		var result []string
		for _, prof := range p.profiles {
			result = append(result, prof.region+"|"+prof.up.meta["AWS_REGION"])
		}
		return result
	}

	opts := base()
	opts.Profiles = append(
		opts.Profiles,
		Profile{Name: "b", Account: "B", Role: "R", Region: "us-west-2"},
	)
	opts.DefaultRegion = "eu-central-1"
	if got := strings.Join(
		regions(opts),
		",",
	); got != "eu-central-1|eu-central-1,us-west-2|us-west-2" {
		t.Errorf("default regions = %s", got)
	}

	opts.Region = "eu-west-1"
	if got := strings.Join(regions(opts), ","); got != "eu-west-1|eu-west-1,us-west-2|us-west-2" {
		t.Errorf("-region regions = %s", got)
	}

	opts.Region = ""
	opts.Metadata = map[string]string{"AWS_REGION": "eu-west-3"}
	if got := strings.Join(regions(opts), ","); got != "eu-west-3|eu-west-3,us-west-2|us-west-2" {
		t.Errorf("-metadata regions = %s", got)
	}
}

func TestStopsWhenCancelled(t *testing.T) {
	server := newFakeServer(t)
	cachePath := filepath.Join(t.TempDir(), "cache.json")
	writeCache(t, server, cachePath, `[]`)

	proxy, err := New(Options{
		Endpoint:       server.URL + "/mcp",
		Profiles:       []Profile{{Name: "sb", Account: "Sandbox", Role: "RO"}},
		Service:        "aws-mcp",
		SigningRegion:  "us-east-1",
		CachePath:      cachePath,
		httpClient:     server.Client(),
		newCredentials: func(Profile) aws.CredentialsProvider { return &fakeCredentials{calls: &atomic.Int32{}} },
	})
	if err != nil {
		t.Fatal(err)
	}

	// stdin stays open, as it does when a client sends SIGTERM
	inReader, inWriter := io.Pipe()
	defer inWriter.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(ctx, inReader, io.Discard) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve didn't stop when cancelled")
	}
}

func TestCancelsToolCall(t *testing.T) {
	server := newFakeServer(t)
	_, client := startProxy(t, server, Options{
		Profiles: []Profile{{Name: "sb", Account: "Sandbox", Role: "RO"}},
	})
	client.initialize()

	waitForMethod := func(method string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !slices.Contains(server.methods(), method) {
			if time.Now().After(deadline) {
				t.Fatalf("upstream was never sent %s: %v", method, server.methods())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	client.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"slow"}}`)
	waitForMethod("tools/call")
	client.send(
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
	)

	// the call stops, and the cancellation is passed on to the upstream that
	// was handling it
	resp := client.receive()
	if string(resp.ID) != "1" {
		t.Fatalf("got response for %s, want 1", resp.ID)
	}
	toolText(t, resp)
	waitForMethod("notifications/cancelled")
}

func TestNotificationsDontAskForCredentials(t *testing.T) {
	server := newFakeServer(t)
	calls := &atomic.Int32{}
	up := &upstream{
		endpoint:  server.URL + "/mcp",
		http:      server.Client(),
		signer:    newSigner("aws-mcp", "us-east-1"),
		creds:     &fakeCredentials{calls: calls},
		connected: true,
		sessionId: "session-1",
	}
	cancelled := &message{
		JSONRPC: "2.0",
		Method:  "notifications/cancelled",
		Params:  jsontext.Value(`{"requestId":1}`),
	}

	// the credentials have expired since the last request, so the
	// notification is dropped rather than asking for new ones
	up.lastCreds = aws.Credentials{
		AccessKeyID:     "AKID",
		SecretAccessKey: "SECRET",
		CanExpire:       true,
		Expires:         time.Now().Add(-time.Minute),
	}
	up.notify(context.Background(), cancelled)
	if slices.Contains(server.methods(), "notifications/cancelled") {
		t.Error("the notification was sent with expired credentials")
	}

	// with credentials that are still valid, it's sent with those
	up.lastCreds.Expires = time.Now().Add(time.Hour)
	up.notify(context.Background(), cancelled)
	if !slices.Contains(server.methods(), "notifications/cancelled") {
		t.Error("the notification wasn't sent")
	}

	if calls.Load() != 0 {
		t.Errorf("credentials were asked for %d times, want 0", calls.Load())
	}
}
