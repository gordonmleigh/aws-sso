package cmd

import (
	"errors"
	"flag"
	"slices"
	"testing"
	"time"

	"github.com/gordonmleigh/aws-sso/mcpproxy"
)

func TestParseMcpProxy(t *testing.T) {
	cmd, err := parseMcpProxy(CommandMcpProxy, []string{
		"-profile", "sb=Sandbox/ReadOnly",
		"-profile=Production/ReadOnly@us-east-1",
		"-metadata", "A=1",
		"-approval-ttl", "15m",
		"-region", "eu-central-1",
		"-sso-session", "work",
		"-cache", "/tmp/cache.json",
		"-service", "svc",
		"-signing-region", "us-west-2",
		"-debug",
		"-refresh",
		"https://aws-mcp.us-east-1.api.aws/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	c := cmd.(*mcpProxyCmd)

	want := []mcpproxy.Profile{
		{Name: "sb", Account: "Sandbox", Role: "ReadOnly"},
		{Name: "Production", Account: "Production", Role: "ReadOnly", Region: "us-east-1"},
	}
	if !slices.Equal(c.profiles, want) {
		t.Errorf("profiles = %+v", c.profiles)
	}
	if c.endpoint != "https://aws-mcp.us-east-1.api.aws/mcp" || c.metadata["A"] != "1" ||
		c.approvalTtl == nil || *c.approvalTtl != 15*time.Minute ||
		c.region != "eu-central-1" || c.ssoSession != "work" ||
		c.cachePath != "/tmp/cache.json" || c.service != "svc" ||
		c.signingRegion != "us-west-2" || !c.debug || !c.refresh {
		t.Errorf("got %+v", c)
	}

	cmd, err = parseMcpProxy(
		CommandMcpProxy,
		[]string{"-profile", "Sandbox/ReadOnly", "--", "https://example.com/mcp"},
	)
	if err != nil {
		t.Fatal(err)
	}
	c = cmd.(*mcpProxyCmd)
	if c.endpoint != "https://example.com/mcp" || c.approvalTtl != nil {
		t.Errorf("got %+v", c)
	}

	invalid := [][]string{
		{},
		{"-profile", "Sandbox/ReadOnly"},
		{"-profile", "Sandbox/ReadOnly", "https://a.example.com", "https://b.example.com"},
		{"-profile", "Sandbox", "https://example.com"},
		{"-approval-ttl", "-1m", "https://example.com"},
		{"-unknown", "https://example.com"},
	}
	for _, arguments := range invalid {
		if _, err := parseMcpProxy(CommandMcpProxy, arguments); err == nil {
			t.Errorf("Parse(%q) should fail", arguments)
		}
	}

	if _, err := parseMcpProxy(CommandMcpProxy, []string{"-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: got %v, want flag.ErrHelp", err)
	}
}

func TestEndpointHost(t *testing.T) {
	tests := map[string]string{
		"https://aws-mcp.us-east-1.api.aws/mcp":                           "aws-mcp.us-east-1.api.aws",
		"https://aws-mcp.us-east-1.api.aws:443/mcp":                       "aws-mcp.us-east-1.api.aws",
		"https://aws-mcp.us-east-1.api.aws.evil.example/a/very/long/path": "aws-mcp.us-east-1.api.aws.evil.example",
		"https://localhost:8443/mcp":                                      "localhost:8443",
		"https://user:pass@example.com/mcp":                               "example.com",
		"https://[::1]:8443/mcp":                                          "[::1]:8443",
		// the first a is Cyrillic
		"https://\u0430ws-mcp.us-east-1.api.aws/mcp": "xn--ws-mcp-2nf.us-east-1.api.aws",
		// a full-width a, which IDNA maps to an ordinary one
		"https://\uff41ws-mcp.us-east-1.api.aws/mcp": "aws-mcp.us-east-1.api.aws",
	}
	for in, want := range tests {
		if got, err := endpointHost(in); err != nil || got != want {
			t.Errorf("endpointHost(%q) = %q, %v, want %q", in, got, err, want)
		}
	}

	invalid := []string{
		"http://example.com/mcp",
		"https:///mcp",
		"example.com",
		"://",
		// a label can't start with a combining mark
		"https://\u0301aws-mcp.us-east-1.api.aws/mcp",
	}
	for _, in := range invalid {
		if _, err := endpointHost(in); err == nil {
			t.Errorf("endpointHost(%q) should fail", in)
		}
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		in   string
		want mcpproxy.Profile
	}{
		{
			"Sandbox/ReadOnly",
			mcpproxy.Profile{Name: "Sandbox", Account: "Sandbox", Role: "ReadOnly"},
		},
		{
			"sb=Sandbox/ReadOnly",
			mcpproxy.Profile{Name: "sb", Account: "Sandbox", Role: "ReadOnly"},
		},
		{
			"sb=123456789012/ReadOnly@eu-west-1",
			mcpproxy.Profile{
				Name:    "sb",
				Account: "123456789012",
				Role:    "ReadOnly",
				Region:  "eu-west-1",
			},
		},
		{
			"My Account/ReadOnly@us-gov-west-1",
			mcpproxy.Profile{
				Name:    "My Account",
				Account: "My Account",
				Role:    "ReadOnly",
				Region:  "us-gov-west-1",
			},
		},
		// not a region, so part of the role name
		{
			"Sandbox/Role@team",
			mcpproxy.Profile{Name: "Sandbox", Account: "Sandbox", Role: "Role@team"},
		},
		{"a/b/Role", mcpproxy.Profile{Name: "a/b", Account: "a/b", Role: "Role"}},
	}
	for _, tt := range tests {
		got, err := parseProfile(tt.in)
		if err != nil {
			t.Errorf("parseProfile(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseProfile(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}

	for _, in := range []string{"", "Sandbox", "=Sandbox/Role", "x=/Role", "x=Sandbox/", "Sandbox/@eu-west-1"} {
		if _, err := parseProfile(in); err == nil {
			t.Errorf("parseProfile(%q) should fail", in)
		}
	}
}

func TestEndpointHostFromArgs(t *testing.T) {
	tests := map[string]struct {
		endpoint string
		want     string
		wantErr  bool
	}{
		"https":     {"https://aws-mcp.us-east-1.api.aws/mcp", "aws-mcp.us-east-1.api.aws", false},
		"not https": {"http://example.com", "", true},
	}
	for name, tt := range tests {
		cmd, err := parseMcpProxy(CommandMcpProxy, []string{"-profile", "a/b", tt.endpoint})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		got, err := cmd.(*mcpProxyCmd).EndpointHost()
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf(
				"%s: EndpointHost() = %q, %v, want %q (error %v)",
				name,
				got,
				err,
				tt.want,
				tt.wantErr,
			)
		}
	}
}
