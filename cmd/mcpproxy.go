package cmd

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/gordonmleigh/aws-sso/agent"
	"github.com/gordonmleigh/aws-sso/awsenv"
	"github.com/gordonmleigh/aws-sso/config"
	"github.com/gordonmleigh/aws-sso/mcpproxy"
	"golang.org/x/net/idna"
)

// CommandMcpProxy is the subcommand that runs this command.
const CommandMcpProxy = "mcp-proxy"

var regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

type mcpProxyCmd struct {
	// endpoint is the URL of the remote MCP server
	endpoint string
	profiles []mcpproxy.Profile
	metadata map[string]string
	// approvalTtl is nil if not given
	approvalTtl   *time.Duration
	cachePath     string
	debug         bool
	region        string
	refresh       bool
	service       string
	signingRegion string
	ssoSession    string
}

// parseMcpProxy parses the arguments after the mcp-proxy subcommand. For -h or -help
// it returns flag.ErrHelp, once the usage has been printed. The usage and
// errors go to stderr, as stdout is for the MCP client.
func parseMcpProxy(name string, args []string) (Command, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	flags.Usage = func() {
		fmt.Fprintf(
			flags.Output(),
			"Usage: %s [flags] <endpoint-url>\n\n%s\n\n",
			name,
			"Runs a stdio MCP server that passes requests to a remote MCP server, signed with SigV4.",
		)
		flags.PrintDefaults()
	}

	c := &mcpProxyCmd{metadata: map[string]string{}}

	flags.Func(
		"profile",
		"An account and role to sign with, as `[name=]account/role[@region]`; repeatable (the first is the default)",
		func(s string) error {
			profile, err := parseProfile(s)
			if err != nil {
				return err
			}
			c.profiles = append(c.profiles, profile)
			return nil
		},
	)
	flags.Func(
		"metadata",
		"Add `key=value` to the _meta of every request; repeatable",
		func(s string) error {
			key, value, err := parseMetadata(s)
			if err != nil {
				return err
			}
			c.metadata[key] = value
			return nil
		},
	)
	flags.Func(
		"approval-ttl",
		"How long to remember approval, as a `duration` like 15m (default: until the next SSO login; 0 to always ask)",
		func(s string) error {
			ttl, err := parseApprovalTtl(s)
			if err != nil {
				return err
			}
			c.approvalTtl = &ttl
			return nil
		},
	)
	flags.StringVar(&c.cachePath, "cache", "", "Where to cache what the server lists")
	flags.BoolVar(&c.debug, "debug", false, "Enable debug logging")
	flags.StringVar(
		&c.region,
		"region",
		"",
		"The AWS region for profiles that don't give their own",
	)
	flags.BoolVar(
		&c.refresh,
		"refresh",
		false,
		"Connect to the server, cache what it lists, and exit",
	)
	flags.StringVar(
		&c.service,
		"service",
		"",
		"The SigV4 service name (default: from the endpoint)",
	)
	flags.StringVar(
		&c.signingRegion,
		"signing-region",
		"",
		"The SigV4 region (default: from the endpoint)",
	)
	flags.StringVar(&c.ssoSession, "sso-session", "", "The name of the SSO session to use")

	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() != 1 {
		err := errors.New("expected exactly one endpoint URL")
		fmt.Fprintln(flags.Output(), err)
		flags.Usage()
		return nil, err
	}
	c.endpoint = flags.Arg(0)
	return c, nil
}

func (c *mcpProxyCmd) Debug() bool {
	return c.debug
}

func (c *mcpProxyCmd) EndpointHost() (string, error) {
	return endpointHost(c.endpoint)
}

func (c *mcpProxyCmd) Run(ctx context.Context) error {
	cfg, err := config.Open()
	if err != nil {
		return err
	}
	sso := cfg.ResolveSso(config.SsoSettings{Session: c.ssoSession})
	if !sso.Complete() {
		return errors.New("SSO configuration is incomplete")
	}

	proxy, err := mcpproxy.New(mcpproxy.Options{
		Endpoint: c.endpoint,
		Profiles: c.profiles,
		Metadata: c.metadata,
		Region:   c.region,
		// the AWS region from the environment or the default profile, as for
		// the CLI, and otherwise the SSO region
		DefaultRegion: cmp.Or(
			awsenv.Load().Region,
			cfg.GetProfileSetting("default", "region"),
			sso.Region,
		),
		Service:       c.service,
		SigningRegion: c.signingRegion,
		CachePath:     c.cachePath,
		Agent: &agent.Client{
			ApprovalTtl: c.approvalTtl,
			Region:      sso.Region,
			StartUrl:    sso.StartUrl,
		},
	})
	if err != nil {
		return err
	}

	if c.refresh {
		count, err := proxy.Refresh(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Cached %d tools from %s in %s\n", count, c.endpoint, proxy.CachePath())
		return nil
	}
	return proxy.Serve(ctx, os.Stdin, os.Stdout)
}

// parseProfile parses `[name=]account/role[@region]`. The name defaults to the
// account as written.
func parseProfile(s string) (mcpproxy.Profile, error) {
	var p mcpproxy.Profile
	rest := s

	if name, after, ok := strings.Cut(rest, "="); ok {
		p.Name = strings.TrimSpace(name)
		rest = after
		if p.Name == "" {
			return p, fmt.Errorf("invalid profile %q: the name before = is empty", s)
		}
	}

	// role names can contain @, so only treat it as a region if it looks like one
	if i := strings.LastIndex(rest, "@"); i >= 0 && regionPattern.MatchString(rest[i+1:]) {
		p.Region = rest[i+1:]
		rest = rest[:i]
	}

	// role names can't contain /, but account names might
	i := strings.LastIndex(rest, "/")
	if i < 0 {
		return p, fmt.Errorf("invalid profile %q: expected [name=]account/role[@region]", s)
	}
	p.Account = strings.TrimSpace(rest[:i])
	p.Role = strings.TrimSpace(rest[i+1:])
	if p.Account == "" || p.Role == "" {
		return p, fmt.Errorf("invalid profile %q: account and role are required", s)
	}

	if p.Name == "" {
		p.Name = p.Account
	}
	return p, nil
}

// parseMetadata parses `key=value`.
func parseMetadata(s string) (string, string, error) {
	key, value, ok := strings.Cut(s, "=")
	if !ok || key == "" {
		return "", "", errors.New("expected key=value")
	}
	return key, value, nil
}

// endpointHost returns the host of an https:// endpoint to show the user: the
// whole hostname, with the port if it isn't 443. A hostname that isn't plain
// ASCII is converted to punycode the same way net/http does before connecting,
// so it shows the host that's really contacted, and lookalike characters
// stand out.
func endpointHost(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf("not an https:// URL: %s", endpoint)
	}

	host := u.Hostname()
	if strings.ContainsFunc(host, func(r rune) bool { return r > unicode.MaxASCII }) {
		if host, err = idna.Lookup.ToASCII(host); err != nil {
			return "", fmt.Errorf("invalid hostname in %s: %w", endpoint, err)
		}
	}
	if port := u.Port(); port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	}
	return host, nil
}
