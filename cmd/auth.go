package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/x/term"
	"github.com/gordonmleigh/aws-sso/agent"
	"github.com/gordonmleigh/aws-sso/auth"
	"github.com/gordonmleigh/aws-sso/awsenv"
	"github.com/gordonmleigh/aws-sso/config"
	"github.com/gordonmleigh/aws-sso/env"
	"github.com/gordonmleigh/aws-sso/sso"
)

type authCmd struct {
	account         string
	approvalTtl     *time.Duration
	args            []string
	assumeRole      string
	debug           bool
	noInput         bool
	outputFormat    string
	region          string
	roleSessionName string
	ssoRole         string

	mu     sync.Mutex
	agent  *agent.Client
	env    *awsenv.AwsEnv
	ssoCfg config.SsoSettings
}

func parseAuth(name string, arguments []string) (Command, error) {
	c := &authCmd{}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)

	flags.Usage = func() {
		out := flags.Output()
		fmt.Fprintf(out, "Usage: %s [flags] [--] [command [args...]]\n", name)
		fmt.Fprintf(
			out,
			"       %s %s [-debug] [install [-debug] | uninstall]\n",
			name,
			CommandAgent,
		)
		fmt.Fprintf(
			out,
			"       %s %s [flags] <endpoint-url>\n\n",
			name,
			CommandMcpProxy,
		)
		fmt.Fprintf(
			out,
			"Gets AWS credentials through AWS SSO, and runs command (or your shell) with them.\n",
		)
		fmt.Fprintf(
			out,
			"Use -h after %s or %s for their flags. Put -- before a command with the same name.\n\n",
			CommandAgent,
			CommandMcpProxy,
		)
		flags.PrintDefaults()
	}

	flags.StringVar(&c.account, "account", "", "The AWS account ID or name to select")
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
	flags.StringVar(
		&c.assumeRole,
		"assume-role",
		"",
		"ARN of a role to assume after authenticating",
	)
	flags.BoolVar(&c.debug, "debug", false, "Enable debug logging")
	flags.BoolVar(&c.noInput, "no-input", false, "True to avoid asking the user anything")
	flags.StringVar(&c.region, "region", "", "The AWS region to use")
	flags.StringVar(
		&c.roleSessionName,
		"role-session-name",
		"",
		"Value to use for the role session name for the assume role operation",
	)
	flags.StringVar(&c.ssoRole, "role", "", "The name of the SSO role to assume")
	flags.StringVar(&c.ssoCfg.Region, "sso-region", "", "The AWS region for SSO")
	flags.StringVar(&c.ssoCfg.Session, "sso-session", "", "The name of the SSO session to use")

	flags.Func("output", "Output format ('json' or 'env' or 'export')", func(s string) error {
		if s != "json" && s != "env" && s != "export" {
			return errors.New("invalid output format, must be 'json', 'env' or 'export'")
		}
		c.outputFormat = s
		if s == "json" {
			c.noInput = true
		}
		return nil
	})

	if err := flags.Parse(arguments); err != nil {
		return nil, err
	}
	c.args = flags.Args()

	return c, nil
}

func (c *authCmd) Debug() bool {
	return c.debug
}

func (c *authCmd) Run(ctx context.Context) error {
	if err := c.init(); err != nil {
		return err
	}

	account, err := c.resolveAccount(ctx)
	if err != nil {
		return err
	}

	ssoRole, err := c.resolveSsoRole(ctx, account.AccountId)
	if err != nil {
		return err
	}

	// cached, so that the user only approves the SSO credentials once
	var provider aws.CredentialsProvider = aws.NewCredentialsCache(&auth.SsoProvider{
		Account: account.AccountId,
		Agent:   c.agent,
		Config:  c.ssoCfg,
		SsoRole: ssoRole,
	})

	roleSessionName := c.roleSessionName

	if c.assumeRole != "" {
		stsClient := sts.New(sts.Options{
			Credentials: provider,
			Region:      c.region,
		})

		if roleSessionName == "" {
			// propagate parent's role session name, which will be the SSO username
			identity, err := c.withSpinner(
				ctx,
				"Getting caller identity...",
				func(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
					return stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
				},
			)
			if err != nil {
				// assuming the role needs the same credentials, so it would fail too
				return fmt.Errorf("failed to get caller identity: %w", err)
			}
			log.Printf("[DEBUG] got caller identity: %s\n", aws.ToString(identity.UserId))
			roleSessionName = getSessionName(aws.ToString(identity.UserId))
			log.Printf("[DEBUG] using role session name %s\n", roleSessionName)
		}

		provider = &auth.AssumeRoleProvider{
			RoleARN:         c.assumeRole,
			RoleSessionName: roleSessionName,
			STS:             stsClient,
		}
	}

	creds, err := c.withSpinner(
		ctx,
		"Assuming role...",
		provider.Retrieve,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve credentials: %w", err)
	}

	authEnv := &awsenv.AwsEnv{
		AccessKeyId:     creds.AccessKeyID,
		Expiration:      &creds.Expires,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Region:          c.region,
	}

	if c.assumeRole != "" {
		assumeRoleName := c.assumeRole[strings.Index(c.assumeRole, "/")+1:]
		authEnv.SsoProfile = "assumed-role/" + creds.AccountID + "/" + assumeRoleName

		if roleSessionName != "" {
			authEnv.SsoProfile += "/" + roleSessionName
		}
	} else {
		authEnv.SsoProfile = fmt.Sprintf(
			"%s/%s/%s",
			account.AccountId,
			account.AccountName,
			ssoRole,
		)
	}

	switch c.outputFormat {
	case "json":
		data, err := authEnv.JsonString()
		if err != nil {
			return err
		}
		fmt.Println(data)
	case "env":
		fmt.Println(authEnv.Env().String())
	case "export":
		fmt.Println(authEnv.Env().Export())
	default:
		var exe string
		var args []string

		if len(c.args) > 0 {
			exe = c.args[0]
			args = c.args
		} else {
			exe = os.Getenv("SHELL")
			if exe == "" {
				return errors.New("no command provided and SHELL not set in environment")
			}
			args = []string{exe}
		}

		bin, err := exec.LookPath(exe)
		if err != nil {
			return err
		}

		e := env.Current()
		e.Merge(authEnv.Env())

		return syscall.Exec(bin, args, e.Slice())
	}
	return nil
}

func (c *authCmd) init() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.agent != nil {
		// already initialized
		return nil
	}

	if !c.ssoCfg.Complete() {
		cfg, err := config.Open()
		if err != nil {
			return err
		}

		resolvedCfg := cfg.ResolveSso(c.ssoCfg)
		if resolvedCfg.Complete() {
			c.ssoCfg = resolvedCfg
			log.Printf("[DEBUG] SSO config resolved as %v\n", c.ssoCfg)
		} else {
			return errors.New("SSO configuration is incomplete")
		}
	}

	c.agent = &agent.Client{
		Region:      c.ssoCfg.Region,
		StartUrl:    c.ssoCfg.StartUrl,
		ApprovalTtl: c.approvalTtl,
	}

	c.env = awsenv.Load()

	if c.region == "" {
		if c.env.Region != "" {
			c.region = c.env.Region
		} else {
			cfgFile, err := config.Open()
			if err != nil {
				// just log and continue
				log.Printf("[DEBUG] failed to open config file: %v\n", err)
			} else {
				// use the region from the default config
				c.region = cfgFile.GetProfileSetting("default", "region")
			}
			if c.region == "" {
				// fall back to SSO region
				c.region = c.ssoCfg.Region
			}
		}
		log.Printf("[DEBUG] resolved AWS region to %s\n", c.region)
	}

	return nil
}

func (c *authCmd) listRoles(ctx context.Context, accountId string) ([]string, error) {
	roles, err := c.agent.ListRoles(ctx, accountId)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO roles: %w", err)
	}

	var roleNames []string
	for _, role := range roles {
		roleNames = append(roleNames, role.RoleName)
	}
	return roleNames, nil
}

func (c *authCmd) resolveAccount(ctx context.Context) (sso.AccountInfo, error) {
	// the agent logs in through the browser if needed
	accounts, err := c.withSpinner(
		ctx,
		"Loading AWS accounts...",
		c.agent.ListAccounts,
	)
	if err != nil {
		return sso.AccountInfo{}, fmt.Errorf("failed to get accounts: %w", err)
	}
	if len(accounts) == 0 {
		return sso.AccountInfo{}, errors.New("no accounts available")
	}
	if c.account != "" {
		for _, account := range accounts {
			if account.AccountId == c.account || account.AccountName == c.account {
				return account, nil
			}
		}
		return sso.AccountInfo{}, fmt.Errorf("no account found matching %s", c.account)
	}
	if len(accounts) == 1 {
		return accounts[0], nil
	}

	if c.noInput {
		return sso.AccountInfo{}, errors.New(
			"non-interactive mode: more than one account available",
		)
	}

	options := []huh.Option[sso.AccountInfo]{}
	for _, account := range accounts {
		options = append(options, huh.Option[sso.AccountInfo]{
			Value: account,
			Key:   fmt.Sprintf("%s (%s)", account.AccountName, account.AccountId),
		})
	}

	var selection sso.AccountInfo

	err = huh.NewSelect[sso.AccountInfo]().
		Title("Select an AWS account").
		Options(options...).
		Value(&selection).
		Run()
	if err != nil {
		return sso.AccountInfo{}, err
	}

	log.Printf("[DEBUG] selected account id %s\n", selection.AccountId)
	return selection, nil
}

func (c *authCmd) resolveSsoRole(ctx context.Context, accountId string) (string, error) {
	roles, err := c.withSpinner(
		ctx,
		"Loading SSO roles...",
		func(ctx context.Context) ([]string, error) {
			return c.listRoles(ctx, accountId)
		},
	)
	if err != nil {
		return "", err
	}
	if len(roles) == 0 {
		return "", errors.New("no roles available")
	}
	if c.ssoRole != "" {
		if slices.Contains(roles, c.ssoRole) {
			return c.ssoRole, nil
		}
		return "", fmt.Errorf("no role found matching %s", c.ssoRole)
	}
	if len(roles) == 1 {
		return roles[0], nil
	}

	if c.noInput {
		return "", errors.New("non-interactive mode: more than one role available")
	}

	var selection string

	err = huh.NewSelect[string]().
		Title("Select an SSO role").
		Options(huh.NewOptions(roles...)...).
		Value(&selection).
		Run()
	if err != nil {
		return "", err
	}

	log.Printf("[DEBUG] selected role %s\n", selection)
	return selection, nil
}

// withSpinner runs wrapped, showing a spinner on stderr while it runs, unless
// -no-input is set or stderr isn't a terminal. The spinner never goes to
// stdout, which may be the output.
func (c *authCmd) withSpinner[T any](
	ctx context.Context,
	title string,
	wrapped func(context.Context) (T, error),
) (T, error) {
	if c.noInput || !term.IsTerminal(os.Stderr.Fd()) {
		return wrapped(ctx)
	}

	var result T
	err := spinner.New().
		Context(ctx).
		Output(os.Stderr).
		Title(title).
		ActionWithErr(func(ctx context.Context) error {
			var err error
			result, err = wrapped(ctx)
			return err
		}).
		Run()
	if err != nil {
		// if ctx ended, the action may still be running, so don't read result
		var zero T
		return zero, err
	}
	return result, nil
}

func getSessionName(userId string) string {
	_, name, ok := strings.Cut(userId, ":")
	if !ok {
		return ""
	}
	// session names can only have these characters, and up to 64 of
	// them; anything else would make AssumeRole fail
	name = strings.Map(func(r rune) rune {
		if r <= unicode.MaxASCII &&
			(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("_+=,.@-", r)) {
			return r
		}
		return -1
	}, name)
	name = name[:min(len(name), 64)]
	if len(name) >= 2 {
		return name
	}
	return ""
}
