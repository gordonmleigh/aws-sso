package cmd

import (
	"errors"
	"flag"
	"testing"
)

func TestParse(t *testing.T) {
	tests := map[string]struct {
		args      []string
		want      string
		wantDebug bool
	}{
		"default":         {[]string{"-account", "a", "-role", "r"}, "auth", false},
		"default, debug":  {[]string{"-debug"}, "auth", true},
		"custom command":  {[]string{"--", "agent"}, "auth", false},
		"after a flag":    {[]string{"-debug", "agent"}, "auth", true},
		"agent":           {[]string{"agent"}, "agent", false},
		"agent, debug":    {[]string{"agent", "-debug"}, "agent", true},
		"agent install":   {[]string{"agent", "install", "-debug"}, "agent install", true},
		"agent uninstall": {[]string{"agent", "uninstall"}, "agent uninstall", false},
		"mcp-proxy": {
			[]string{"mcp-proxy", "-profile", "a/b", "https://x"},
			"mcp-proxy",
			false,
		},
		"mcp-proxy, debug": {
			[]string{"mcp-proxy", "-debug", "-profile", "a/b", "https://x"},
			"mcp-proxy",
			true,
		},
	}
	for name, tt := range tests {
		cmd, err := Parse("aws-sso", tt.args)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		var got string
		switch cmd.(type) {
		case *authCmd:
			got = "auth"
		case *agentCmd:
			got = "agent"
		case *agentInstallCmd:
			got = "agent install"
		case *agentUninstallCmd:
			got = "agent uninstall"
		case *mcpProxyCmd:
			got = "mcp-proxy"
		}
		if got != tt.want || cmd.Debug() != tt.wantDebug {
			t.Errorf(
				"%s: got %s (debug %v), want %s (debug %v)",
				name,
				got,
				cmd.Debug(),
				tt.want,
				tt.wantDebug,
			)
		}
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string][]string{
		"help":                 {"-h"},
		"agent help":           {"agent", "-h"},
		"agent install help":   {"agent", "install", "-h"},
		"mcp-proxy help":       {"mcp-proxy", "-h"},
		"unknown agent action": {"agent", "bogus"},
		"extra arguments":      {"agent", "uninstall", "now"},
		"no endpoint":          {"mcp-proxy"},
	}
	for name, args := range tests {
		cmd, err := Parse("aws-sso", args)
		if err == nil {
			t.Errorf("%s: no error", name)
		}
		if cmd != nil {
			t.Errorf("%s: got a command (%T) with the error", name, cmd)
		}
		if isHelp := errors.Is(
			err,
			flag.ErrHelp,
		); isHelp != (len(args) > 0 && args[len(args)-1] == "-h") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
