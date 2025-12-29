package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/logutils"
)

func main() {
	log.SetFlags(0)
	appState := &app{}

	flag.StringVar(&appState.account, "account", "", "The AWS account ID or name to select")
	flag.StringVar(&appState.assumeRole, "assume-role", "", "ARN of a role to assume after authenticating")
	flag.BoolVar(&appState.debug, "debug", false, "Enable debug logging")
	flag.BoolVar(&appState.noInput, "no-input", false, "True to avoid asking the user anything")
	flag.StringVar(&appState.region, "region", "", "The AWS region to use")
	flag.StringVar(&appState.roleSessionName, "role-session-name", "", "Value to use for the role session name for the assume role operation")
	flag.StringVar(&appState.ssoRole, "role", "", "The name of the SSO role to assume")
	flag.StringVar(&appState.ssoRegion, "sso-region", "", "The AWS region for SSO")
	flag.StringVar(&appState.ssoSession, "sso-session", "", "The name of the SSO session to use")

	flag.Func("output", "Output format ('json' or 'env' or 'export')", func(s string) error {
		if s != "json" && s != "env" && s != "export" {
			return errors.New("invalid output format, must be 'json', 'env' or 'export'")
		}
		appState.outputFormat = s
		if s == "json" {
			appState.noInput = true
		}
		return nil
	})

	flag.Parse()
	appState.args = flag.Args()

	var level logutils.LogLevel
	if appState.debug {
		level = logutils.LogLevel("DEBUG")
	} else {
		level = logutils.LogLevel("WARN")
	}

	log.SetOutput(&logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "WARN", "ERROR"},
		MinLevel: level,
		Writer:   os.Stderr,
	})

	if err := appState.run(); err != nil {
		fmt.Printf("%v %v\n", errorStyle.Render("ERROR:"), err)
		os.Exit(1)
	}
}
