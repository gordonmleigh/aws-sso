package procinfo

import (
	"testing"

	"github.com/gordonmleigh/aws-sso/darwin"
)

func TestDescribeMcpProxy(t *testing.T) {
	proxy := &darwin.Process{
		Pid:  30,
		Path: "/Users/me/go/bin/aws-sso",
		Args: []string{"aws-sso", "mcp-proxy", "https://aws-mcp.us-east-1.api.aws/mcp"},
	}
	claude := &darwin.Process{Pid: 20, Path: "/Users/me/.local/bin/claude"}
	zsh := &darwin.Process{Pid: 10, Path: "/bin/zsh"}
	terminal := &darwin.Process{
		Pid:  5,
		Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
	}

	caller := &Caller{
		Process:      proxy,
		Signer:       "unsigned",
		Ancestors:    []*darwin.Process{claude, zsh, terminal},
		ParentSigner: "Developer ID Application: Example (TEAM)",
	}
	got := caller.DescribeMcpProxy("aws-mcp.us-east-1.api.aws.evil.example")
	want := "the MCP proxy for aws-mcp.us-east-1.api.aws.evil.example, started by claude " +
		"[🔐 Developer ID Application: Example (TEAM)] (via Terminal → zsh)"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	caller.Ancestors = []*darwin.Process{claude}
	got = caller.DescribeMcpProxy("localhost:8443")
	want = "the MCP proxy for localhost:8443, started by claude [🔐 Developer ID Application: Example (TEAM)]"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	caller.Ancestors = nil
	if got := caller.DescribeMcpProxy("example.com"); got != "the MCP proxy for example.com" {
		t.Errorf("without a parent: got %q", got)
	}
}
