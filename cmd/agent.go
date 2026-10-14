package cmd

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/gordonmleigh/aws-sso/agent"
)

const (
	CommandAgent          = "agent"
	CommandAgentInstall   = "install"
	CommandAgentUninstall = "uninstall"
)

type agentCmd struct {
	debug bool
}

// parseAgent parses the arguments after the agent subcommand. For -h or -help it
// returns flag.ErrHelp, once the usage has been printed.
func parseAgent(name string, args []string) (Command, error) {
	if len(args) > 0 {
		switch args[0] {
		case CommandAgentInstall:
			return parseAgentInstall(name+" "+args[0], args[1:])
		case CommandAgentUninstall:
			return parseAgentUninstall(name+" "+args[0], args[1:])
		}
	}

	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	flags.Usage = func() {
		fmt.Fprintf(
			flags.Output(),
			"Usage: %s [-debug] [install [-debug] | uninstall]\n\n%s\n\n",
			name,
			"With no command, runs the agent (normally started by launchd).",
		)
		flags.PrintDefaults()
	}

	c := &agentCmd{}
	flags.BoolVar(&c.debug, "debug", false, "Enable debug logging")

	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() > 0 {
		err := fmt.Errorf("unexpected arguments: %v", flags.Args())
		fmt.Fprintln(flags.Output(), err)
		flags.Usage()
		return nil, err
	}
	return c, nil
}

// Debug reports whether to log debug messages. For install, that's about the
// install itself, not the installed agent.
func (c *agentCmd) Debug() bool {
	return c.debug
}

func (c *agentCmd) Run(ctx context.Context) error {
	// the agent's log is kept, so it needs timestamps to match up with prompts
	log.SetFlags(log.LstdFlags)

	srv := &agent.Server{
		McpProxy: func(args []string) (string, bool) {
			if len(args) == 0 {
				return "", false
			}
			cmd, err := Parse(args[0], args[1:])
			if err != nil {
				log.Printf("[WARN] error parsing CLI: %v", err)
				return "", false
			}
			proxycmd, ok := cmd.(*mcpProxyCmd)
			if !ok {
				return "", false
			}
			host, err := proxycmd.EndpointHost()
			if err != nil {
				log.Printf("[WARN] error parsing mcp-proxy host: %v", err)
				return "", false
			}
			return host, true
		},
	}
	return srv.Run(ctx)
}

type agentInstallCmd struct {
	debug bool
}

func (c *agentInstallCmd) Debug() bool {
	return c.debug
}

func parseAgentInstall(name string, args []string) (Command, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	flags.Usage = func() {
		fmt.Fprintf(
			flags.Output(),
			"Usage: %s [-debug]\n\n%s\n\n",
			name,
			"Registers the agent with launchd, replacing any previous install.",
		)
		flags.PrintDefaults()
	}

	c := &agentInstallCmd{}
	flags.BoolVar(&c.debug, "debug", false, "Enable debug logging")

	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() > 0 {
		err := fmt.Errorf("unexpected arguments: %v", flags.Args())
		fmt.Fprintln(flags.Output(), err)
		flags.Usage()
		return nil, err
	}
	return c, nil
}

func (c *agentInstallCmd) Run(ctx context.Context) error {
	return agent.Install(agent.InstallOptions{Debug: c.debug})
}

type agentUninstallCmd struct {
	debug bool
}

func (c *agentUninstallCmd) Debug() bool {
	return c.debug
}

func parseAgentUninstall(name string, args []string) (Command, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	flags.Usage = func() {
		fmt.Fprintf(
			flags.Output(),
			"Usage: %s [-debug]\n\n%s\n\n",
			name,
			"Removes the agent from launchd.",
		)
		flags.PrintDefaults()
	}

	c := &agentUninstallCmd{}
	flags.BoolVar(&c.debug, "debug", false, "Enable debug logging")

	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() > 0 {
		err := fmt.Errorf("unexpected arguments: %v", flags.Args())
		fmt.Fprintln(flags.Output(), err)
		flags.Usage()
		return nil, err
	}
	return c, nil
}

func (c *agentUninstallCmd) Run(ctx context.Context) error {
	return agent.Uninstall()
}
