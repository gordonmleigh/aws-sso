package agent

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startTestAgent serves on a temporary socket, and returns its path.
func startTestAgent(t *testing.T) string {
	t.Helper()
	// t.TempDir() can be too long for a socket path
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	path := filepath.Join(dir, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Authorize: func(string) error { return errors.New("no prompts in tests") },
		McpProxy:  func([]string) (string, bool) { return "", false },
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return path
}

// exchange connects, reads the hello, sends line, and returns the response.
func exchange(t *testing.T, path string, line string) (hello, response) {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("agent isn't serving: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	dec := jsontext.NewDecoder(conn)
	var h hello
	if err := json.UnmarshalDecode(dec, &h); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, line+"\n"); err != nil {
		t.Fatal(err)
	}
	var resp response
	if err := json.UnmarshalDecode(dec, &resp); err != nil {
		t.Fatal(err)
	}
	return h, resp
}

func TestAgentRejectsOtherProtocolsWithoutRestarting(t *testing.T) {
	path := startTestAgent(t)

	tests := map[string]string{
		"older version": `{"version":3,"op":"listAccounts","region":"r","startUrl":"u"}`,
		"newer version": `{"version":99,"op":"listAccounts","region":"r","startUrl":"u"}`,
		"invalid":       `{"version":"four"}`,
	}
	for name, line := range tests {
		h, resp := exchange(t, path, line)
		if h.Version != protocolVersion || h.Outdated || h.Error != "" {
			t.Errorf("%s: got hello %+v", name, h)
		}
		if !resp.Outdated {
			t.Errorf("%s: got response %+v, want outdated", name, resp)
		}
	}

	// the agent is still serving, so a matching request gets an answer
	_, resp := exchange(
		t,
		path,
		`{"version":`+strconv.Itoa(protocolVersion)+`,"op":"listAccounts"}`,
	)
	if resp.Outdated || !strings.Contains(resp.Error, "required") {
		t.Errorf("got response %+v, want the missing start URL error", resp)
	}
}

func TestReadError(t *testing.T) {
	var h hello
	err := json.Unmarshal([]byte(`{"version":"four"}`), &h)
	if !errors.Is(readError(err), errOutdated) {
		t.Errorf("an invalid message should say to reinstall, got %v", readError(err))
	}

	if err := readError(io.EOF); errors.Is(err, errOutdated) {
		t.Errorf("a closed connection isn't a protocol error, got %v", err)
	}
	err = json.UnmarshalDecode(jsontext.NewDecoder(strings.NewReader(`{"version":`)), &h)
	if errors.Is(readError(err), errOutdated) {
		t.Errorf("a truncated message isn't a protocol error, got %v", readError(err))
	}
}

func TestServeStopsWhenContextEnds(t *testing.T) {
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	path := filepath.Join(dir, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Authorize: func(string) error { return errors.New("no prompts in tests") },
		McpProxy:  func([]string) (string, bool) { return "", false },
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, listener) }()

	// a request is being handled when the context ends
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var h hello
	if err := json.UnmarshalDecode(jsontext.NewDecoder(conn), &h); err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve didn't stop when its context ended")
	}

	if _, err := net.Dial("unix", path); err == nil {
		t.Error("the agent is still accepting connections")
	}
}
