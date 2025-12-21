package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/hashicorp/logutils"
	"propulsionworks.io/aws-sso/authorizer"
	"propulsionworks.io/aws-sso/config"
)

var cli struct {
	Sso     SsoCommand `cmd:"" help:"Authenticate via SSO"`
	Verbose bool       `short:"v" help:"Show debug logging"`
}

type SsoCommand struct {
	// the order of these corresponds to the CLI order
	SessionName string   `arg:"" help:"The name of the sso-session section in the config file"`
	AccountId   string   `arg:"" help:"The AWS Account ID"`
	RoleName    string   `arg:"" help:"The SSO Role Name"`
	Command     string   `arg:"" help:"A command to execute"                                   optional:""`
	Arguments   []string `arg:"" help:"Arguments for the command"                              optional:""`
}

type CredentialOutput struct {
	AccessKeyId     string
	Expiration      string
	SecretAccessKey string
	SessionToken    string
	Version         int
}

func (c *SsoCommand) Run() error {
	cfg, err := config.Open()
	if err != nil {
		return err
	}

	ssoCfg := cfg.GetSsoConfig(c.SessionName)
	if ssoCfg.Region == "" || ssoCfg.StartUrl == "" {
		return fmt.Errorf("SSO config is invalid for sso-session %s", c.SessionName)
	}

	auth := &authorizer.Authorizer{
		ProfileName: c.SessionName,
		Region:      ssoCfg.Region,
		StartUrl:    ssoCfg.StartUrl,
	}

	ctx := context.Background()

	if err := auth.Authorize(ctx); err != nil {
		return err
	}

	creds, err := auth.GetRoleCredentials(ctx, c.AccountId, c.RoleName, -1)
	if err != nil {
		return err
	}

	expiration := time.Unix(creds.Expiration, 0).Format(time.RFC3339)

	if c.Command != "" {
		bin, err := exec.LookPath(c.Command)
		if err != nil {
			return err
		}

		profileDisplayName := fmt.Sprintf("%s/%s", c.AccountId, c.RoleName)

		env := Environment(os.Environ())

		env.Set("AWS_ACCESS_KEY_ID", creds.AccessKeyId)
		env.Set("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
		env.Set("AWS_SESSION_TOKEN", creds.SessionToken)
		env.Set("AWS_CREDENTIAL_EXPIRATION", expiration)
		env.Set("AWS_SSO_PROFILE", profileDisplayName)

		if env.Get("AWS_REGION") == "" {
			env.Set("AWS_REGION", ssoCfg.Region)
		}

		args := []string{c.Command}
		args = append(args, c.Arguments...)

		err = syscall.Exec(bin, args, env)
		if err != nil {
			return err
		}
	}

	output, err := json.MarshalIndent(
		&CredentialOutput{
			AccessKeyId:     creds.AccessKeyId,
			Expiration:      expiration,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
			Version:         1,
		},
		"",
		"  ",
	)
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}

func main() {
	log.SetFlags(0)
	ctx := kong.Parse(&cli)

	var level logutils.LogLevel
	if cli.Verbose {
		level = logutils.LogLevel("DEBUG")
	} else {
		level = logutils.LogLevel("WARN")
	}

	log.SetOutput(&logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "WARN", "ERROR"},
		MinLevel: level,
		Writer:   os.Stderr,
	})

	if err := ctx.Run(); err != nil {
		log.Printf("[ERROR] %v\n", err)
		os.Exit(1)
	}
}
