package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gordonmleigh/aws-sso/agent"
	"github.com/gordonmleigh/aws-sso/config"
)

var ErrNoSso = errors.New("SSO config not found or incomplete")

type SsoProvider struct {
	Account string
	Agent   *agent.Client
	Config  config.SsoSettings
	SsoRole string
}

var _ aws.CredentialsProvider = (*SsoProvider)(nil)

func (p *SsoProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if !p.Config.Complete() {
		return aws.Credentials{}, ErrNoSso
	}
	creds, err := p.Agent.GetRoleCredentials(ctx, p.Account, p.SsoRole)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to get role credentials: %w", err)
	}
	return creds.Credentials, nil
}
