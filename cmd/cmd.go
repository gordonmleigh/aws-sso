package cmd

import (
	"context"
	"errors"
	"time"
)

// Parse parses the arguments after the program name. For -h or -help it
// returns flag.ErrHelp, once the usage has been printed. Any other error has
// been printed along with the usage, as the flag package does.
func Parse(name string, arguments []string) (Command, error) {
	if len(arguments) > 0 {
		switch arguments[0] {
		case CommandAgent:
			return parseAgent(name+" "+arguments[0], arguments[1:])
		case CommandMcpProxy:
			return parseMcpProxy(name+" "+arguments[0], arguments[1:])
		}
	}
	return parseAuth(name, arguments)
}

type Command interface {
	Debug() bool
	Run(context.Context) error
}

// parseApprovalTtl parses the value of -approval-ttl.
func parseApprovalTtl(s string) (time.Duration, error) {
	ttl, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if ttl < 0 {
		return 0, errors.New("must not be negative")
	}
	return ttl, nil
}
