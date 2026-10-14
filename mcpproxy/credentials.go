package mcpproxy

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gordonmleigh/aws-sso/agent"
)

// agentCredentials gets role credentials for a profile from the agent, which
// asks the user to approve them.
type agentCredentials struct {
	agent *agent.Client
	// account is the account ID or name, which the agent looks up
	account string
	role    string
}

func (c *agentCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := c.agent.GetRoleCredentials(ctx, c.account, c.role)
	if err != nil {
		return aws.Credentials{}, err
	}
	return creds.Credentials, nil
}
