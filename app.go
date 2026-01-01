package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/lipgloss"
	"propulsionworks.io/aws-sso/authorizer"
	"propulsionworks.io/aws-sso/awsenv"
	"propulsionworks.io/aws-sso/config"
	"propulsionworks.io/aws-sso/env"
	"propulsionworks.io/aws-sso/sso"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
var choiceStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))

type app struct {
	auth                 *authorizer.Authorizer
	account              string
	accountId            string
	accountName          string
	args                 []string
	assumeRole           string
	assumeRoleAccountId  string
	assumeRoleName       string
	availableAccounts    []sso.AccountInfo
	availableRoles       []sso.RoleInfo
	availableSsoSessions []string
	awsConfig            *config.AwsConfig
	creds                *aws.Credentials
	ctx                  context.Context
	debug                bool
	noInput              bool
	outputFormat         string
	region               string
	roleSessionName      string
	ssoRegion            string
	ssoRole              string
	ssoSession           string
	ssoStartUrl          string
	sts                  *sts.Client
}

func (m *app) assumeRoleCredentials() error {
	if m.assumeRole == "" {
		return nil
	}
	if m.sts == nil {
		m.sts = sts.NewFromConfig(aws.Config{
			Region:      m.region,
			Credentials: credentials.StaticCredentialsProvider{Value: *m.creds},
		})
	}

	if m.roleSessionName == "" {
		// we'll try to get the current role session name to propagate it
		identity, err := m.sts.GetCallerIdentity(m.ctx, &sts.GetCallerIdentityInput{})
		if err == nil && identity.UserId != nil {
			log.Printf("[DEBUG] got caller identity: %s", *identity.UserId)

			parts := strings.Split(*identity.UserId, ":")
			if len(parts) > 1 {
				log.Printf("[DEBUG] extracted role session name: %s", parts[1])
				m.roleSessionName = parts[1]
			}
		} else {
			if err != nil {
				log.Printf("[DEBUG] failed to get caller identity: %v", err)
			}
			m.roleSessionName = "aws-sso"
		}
	}

	input := &sts.AssumeRoleInput{
		RoleArn: aws.String(m.assumeRole),
	}
	input.RoleSessionName = &m.roleSessionName

	output, err := m.sts.AssumeRole(m.ctx, input)
	if err != nil {
		return fmt.Errorf("failed to assume role %s: %w", m.assumeRole, err)
	}

	m.assumeRoleAccountId = strings.Split(m.assumeRole, ":")[4]
	m.assumeRoleName = m.assumeRole[strings.Index(m.assumeRole, "/")+1:]

	m.creds = &aws.Credentials{
		AccessKeyID:     *output.Credentials.AccessKeyId,
		AccountID:       m.assumeRoleAccountId,
		SecretAccessKey: *output.Credentials.SecretAccessKey,
		SessionToken:    *output.Credentials.SessionToken,
		Source:          "AssumeRole",
		CanExpire:       true,
		Expires:         *output.Credentials.Expiration,
	}
	return nil
}

func (m *app) complete() error {
	authEnv := &awsenv.AwsEnv{
		AccessKeyId:     m.creds.AccessKeyID,
		Expiration:      &m.creds.Expires,
		SecretAccessKey: m.creds.SecretAccessKey,
		SessionToken:    m.creds.SessionToken,
		Region:          m.region,
	}

	if m.assumeRole != "" {
		authEnv.SsoProfile = "assumed-role/" + m.assumeRoleAccountId + "/" + m.assumeRoleName

		if m.roleSessionName != "" {
			authEnv.SsoProfile += "/" + m.roleSessionName
		}
	} else {
		authEnv.SsoProfile = fmt.Sprintf("%s/%s/%s", m.accountId, m.accountName, m.ssoRole)
	}

	if m.outputFormat == "json" {
		data, err := authEnv.JsonString()
		if err != nil {
			return err
		}
		fmt.Println(data)
	} else if m.outputFormat == "env" {
		fmt.Println(authEnv.Env().String())
	} else if m.outputFormat == "export" {
		fmt.Println(authEnv.Env().Export())
	} else {
		var exe string
		var args []string

		if len(m.args) > 0 {
			exe = m.args[0]
			args = m.args
		} else {
			exe = os.Getenv("SHELL")
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

func (m *app) init() error {
	m.ctx = context.Background()

	envConfig := awsenv.Load()
	if envConfig.Region != "" && m.region == "" {
		m.region = envConfig.Region
	}

	if envConfig.Authorized() {
		log.Println("[DEBUG] loading credentials from environment")

		creds, err := envConfig.Retrieve(m.ctx)
		if err != nil {
			return fmt.Errorf("failed to load credentials from environment: %w", err)
		}
		m.creds = &creds
	}

	cfg, err := config.Open()
	if err != nil {
		return err
	}

	m.awsConfig = cfg
	m.availableSsoSessions = m.awsConfig.GetSsoProfiles()

	log.Printf("[DEBUG] available SSO sessions: %v", m.availableSsoSessions)
	return nil
}

func (m *app) initAuth() error {
	if !m.initSso() {
		return errors.New("SSO configuration is incomplete")
	}

	m.auth = &authorizer.Authorizer{
		ProfileName: m.ssoSession,
		Region:      m.ssoRegion,
		StartUrl:    m.ssoStartUrl,
	}

	if err := m.auth.Authorize(m.ctx); err != nil {
		return err
	}

	accounts, err := m.auth.Sso().GetAccounts(m.ctx)
	if err != nil {
		return fmt.Errorf("failed to get accounts: %w", err)
	}
	if len(accounts) == 0 {
		return errors.New("no accounts available")
	}
	if len(accounts) == 1 {
		m.accountId = accounts[0].AccountId
		m.accountName = accounts[0].AccountName
	}
	if m.account != "" {
		for _, account := range accounts {
			if account.AccountId == m.account || account.AccountName == m.account {
				m.accountId = account.AccountId
				m.accountName = account.AccountName
				break
			}
		}
		if m.accountId == "" {
			return fmt.Errorf("no account found matching %s", m.account)
		}
	}
	m.availableAccounts = accounts
	return nil
}

func (m *app) initRoleCredentials() error {
	creds, err := m.auth.GetRoleCredentials(m.ctx, m.accountId, m.ssoRole, -1)
	if err != nil {
		return fmt.Errorf("failed to get role credentials: %w", err)
	}
	m.creds = creds
	return nil
}

func (m *app) initRoles() error {
	roles, err := m.auth.Sso().GetAccountRoles(m.ctx, m.accountId)

	if err != nil {
		return fmt.Errorf("failed to get roles: %w", err)
	}
	if len(roles) == 0 {
		return fmt.Errorf("no roles available for account %s", m.accountId)
	}
	if m.ssoRole != "" {
		found := false
		for _, role := range roles {
			if role.RoleName == m.ssoRole {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("no role found matching %s", m.ssoRole)
		}
	}
	if len(roles) == 1 {
		m.ssoRole = roles[0].RoleName
	}
	m.availableRoles = roles
	return nil
}

func (m *app) initSso() bool {
	if m.ssoSession == "" && len(m.availableSsoSessions) == 1 {
		m.ssoSession = m.availableSsoSessions[0]
	}
	if m.ssoSession != "" {
		ssoCfg := m.awsConfig.GetSsoConfig(m.ssoSession)
		if m.ssoRegion == "" {
			m.ssoRegion = ssoCfg.Region
		}
		if m.ssoStartUrl == "" {
			m.ssoStartUrl = ssoCfg.StartUrl
		}
	}
	if m.region == "" {
		m.region = m.awsConfig.GetProfileSetting("default", "region")

		if m.region == "" {
			m.region = m.ssoRegion
		}
	}
	if m.ssoRegion == "" {
		m.ssoRegion = m.region
	}

	return m.ssoRegion != "" && m.ssoStartUrl != ""
}

func (m *app) run() error {
	if !m.noInput {
		return m.runInteractive()
	}

	if err := m.init(); err != nil {
		return err
	}

	if m.assumeRole == "" || m.creds == nil {
		if err := m.initAuth(); err != nil {
			return err
		}
		if m.accountId == "" {
			return errors.New("non-interactive mode: more than one account available")
		}

		if err := m.initRoles(); err != nil {
			return err
		}
		if m.ssoRole == "" {
			return errors.New("non-interactive mode: more than one role available")
		}

		if err := m.initRoleCredentials(); err != nil {
			return err
		}
	}
	if err := m.assumeRoleCredentials(); err != nil {
		return err
	}

	return m.complete()
}

func (m *app) runInteractive() error {
	log.Println("[DEBUG] running interactive mode")

	err := m.init()
	if err != nil {
		return err
	}

	if m.assumeRole == "" || m.creds == nil {
		err = m.runInteractiveSsoAuth()
		if err != nil {
			return err
		}
	}

	if m.assumeRole != "" {
		err = spinner.New().
			Context(m.ctx).
			Title("Assuming role...").
			ActionWithErr(func(ctx context.Context) error {
				return m.assumeRoleCredentials()
			}).
			Run()

		if err != nil {
			return err
		}
	}

	return m.complete()
}

func (m *app) runInteractiveSsoAuth() error {
	log.Println("[DEBUG] starting interactive SSO auth")

	if !m.initSso() && len(m.availableSsoSessions) > 0 {
		options := []huh.Option[string]{}
		for _, ssoSession := range m.availableSsoSessions {
			options = append(options, huh.Option[string]{
				Value: ssoSession,
				Key:   ssoSession,
			})
		}

		huh.NewSelect[string]().
			Title("Select an SSO session").
			DescriptionFunc(func() string {
				return m.awsConfig.GetSsoConfig(m.ssoSession).StartUrl
			}, &m.ssoSession).
			Options(options...).
			Value(&m.ssoSession).Run()
	}
	if !m.initSso() {
		return errors.New("SSO configuration is incomplete")
	}

	err := spinner.New().
		Context(m.ctx).
		Title("Authorizing SSO session...").
		ActionWithErr(func(ctx context.Context) error {
			return m.initAuth()
		}).
		Run()

	if err != nil {
		return err
	}

	if m.accountId == "" {
		accountOptions := []huh.Option[string]{}
		for _, account := range m.availableAccounts {
			accountOptions = append(accountOptions, huh.Option[string]{
				Value: account.AccountId,
				Key:   fmt.Sprintf("%s (%s)", account.AccountName, account.AccountId),
			})
		}

		err = huh.NewSelect[string]().
			Title("Select an AWS account").
			Options(accountOptions...).
			Value(&m.accountId).
			Run()

		if err != nil {
			return err
		}
		log.Printf("[DEBUG] selected account id %s", m.accountId)

		for _, account := range m.availableAccounts {
			if account.AccountId == m.accountId {
				m.accountName = account.AccountName
				break
			}
		}
	}

	err = spinner.New().
		Context(m.ctx).
		Title("Loading SSO roles...").
		ActionWithErr(func(ctx context.Context) error {
			return m.initRoles()
		}).
		Run()

	if err != nil {
		return err
	}

	if m.ssoRole == "" {
		roleOptions := []huh.Option[string]{}

		for _, role := range m.availableRoles {
			roleOptions = append(roleOptions, huh.Option[string]{
				Value: role.RoleName,
				Key:   role.RoleName,
			})
		}

		err = huh.NewSelect[string]().
			Title("Select an SSO role").
			Options(roleOptions...).
			Value(&m.ssoRole).
			Run()

		if err != nil {
			return err
		}
	}

	return spinner.New().
		Context(m.ctx).
		Title("Getting role credentials...").
		ActionWithErr(func(ctx context.Context) error {
			return m.initRoleCredentials()
		}).
		Run()
}
