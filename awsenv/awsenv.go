package awsenv

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"propulsionworks.io/aws-sso/env"
)

type AwsEnv struct {
	AccessKeyId     string
	Expiration      *time.Time `json:",omitempty"`
	Region          string
	SecretAccessKey string
	SessionToken    string
	SsoProfile      string `json:"-"`
	Version         AwsEnvVersion
}

func Load() *AwsEnv {
	env := &AwsEnv{
		Region: os.Getenv("AWS_REGION"),
	}
	if env.Region == "" {
		env.Region = os.Getenv("AWS_DEFAULT_REGION")
	}
	env.AccessKeyId = os.Getenv("AWS_ACCESS_KEY_ID")
	env.SecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
	env.SessionToken = os.Getenv("AWS_SESSION_TOKEN")

	if v := os.Getenv("AWS_CREDENTIAL_EXPIRATION"); v != "" {
		exp, err := time.Parse(time.RFC3339, v)
		if err != nil {
			log.Printf("[WARN] failed to parse AWS_CREDENTIAL_EXPIRATION: %v", err)
		}
		env.Expiration = &exp
	}
	return env
}

func (a *AwsEnv) Authorized() bool {
	return a.AccessKeyId != "" && a.SecretAccessKey != ""
}

func (a *AwsEnv) Env() *env.Environment {
	e := env.New()

	e.Set("AWS_ACCESS_KEY_ID", a.AccessKeyId)
	e.Set("AWS_SECRET_ACCESS_KEY", a.SecretAccessKey)
	e.Set("AWS_SESSION_TOKEN", a.SessionToken)

	if a.Expiration != nil {
		e.Set("AWS_CREDENTIAL_EXPIRATION", a.Expiration.UTC().Format(time.RFC3339))
	}
	if a.Region != "" {
		e.Set("AWS_REGION", a.Region)
	}
	if a.SsoProfile != "" {
		e.Set("AWS_SSO_PROFILE", a.SsoProfile)
	}
	return e
}

func (env *AwsEnv) JsonString() (string, error) {
	b, err := json.MarshalIndent(env, "", "  ")
	return string(b), err
}

func (env *AwsEnv) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if !env.Authorized() {
		return aws.Credentials{}, fmt.Errorf("no credentials loaded")
	}
	creds := aws.Credentials{
		AccessKeyID:     env.AccessKeyId,
		SecretAccessKey: env.SecretAccessKey,
		SessionToken:    env.SessionToken,
		Source:          "Environment",
		CanExpire:       env.Expiration != nil,
	}
	if env.Expiration != nil {
		creds.Expires = *env.Expiration
	}
	return creds, nil
}

type AwsEnvVersion struct{}

func (v AwsEnvVersion) MarshalJSON() ([]byte, error) {
	return []byte("1"), nil
}
