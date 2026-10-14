package auth

import (
	"cmp"
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type AssumeRoleProvider struct {
	RoleARN         string
	RoleSessionName string
	STS             *sts.Client
}

var _ aws.CredentialsProvider = (*AssumeRoleProvider)(nil)

func (p *AssumeRoleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	r, err := p.STS.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(p.RoleARN),
		RoleSessionName: aws.String(cmp.Or(p.RoleSessionName, "aws-sso")),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to assume role %s: %w", p.RoleARN, err)
	}

	creds := aws.Credentials{
		AccessKeyID:     aws.ToString(r.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(r.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(r.Credentials.SessionToken),
		Source:          "AssumeRole",
		CanExpire:       true,
		Expires:         aws.ToTime(r.Credentials.Expiration),
	}
	if user := r.AssumedRoleUser; user != nil {
		if parsed, err := arn.Parse(aws.ToString(user.Arn)); err == nil {
			creds.AccountID = parsed.AccountID
		}
	}

	return creds, nil
}
