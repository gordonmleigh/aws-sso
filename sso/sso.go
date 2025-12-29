package sso

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssoidcTypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"golang.org/x/oauth2"
)

var (
	accountAccessScope  = "sso:account:access"
	defaultScopes       = []string{accountAccessScope}
	defaultCallbackPort = 65065
)

var (
	ErrRefreshTokenInvalid = fmt.Errorf("refresh token is invalid")
)

type Sso struct {
	Region   string
	StartUrl string

	oauth      oauth2.Config
	oidcClient *ssooidc.Client
	ssoClient  *sso.Client
	state      string
	tokens     SsoTokens
	verifier   string
}

type AccountInfo struct {
	AccountId    string
	AccountName  string
	EmailAddress string
}

type RoleInfo struct {
	AccountId string
	RoleName  string
}

type ClientCredentials struct {
	ClientId     string
	ClientSecret string
	ExpiresAt    int64
}

type SsoTokens struct {
	AccessToken  string
	ClientId     string
	RefreshToken string
	ExpiresAt    int64
}

func (client *Sso) ClientId() string {
	return client.oauth.ClientID
}

func (client *Sso) ConfigureClient(credentials *ClientCredentials) {
	client.oauth = oauth2.Config{
		ClientID:     credentials.ClientId,
		ClientSecret: credentials.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL: fmt.Sprintf("https://oidc.%s.amazonaws.com/authorize", client.Region),
		},
		RedirectURL: fmt.Sprintf("http://127.0.0.1:%d", defaultCallbackPort),
		Scopes:      defaultScopes,
	}
}

func (client *Sso) RegisterClient(ctx context.Context, name string) (*ClientCredentials, error) {
	if client.oidcClient == nil {
		client.oidcClient = ssooidc.New(ssooidc.Options{Region: client.Region})
	}
	redirectUrl := fmt.Sprintf("http://127.0.0.1:%d", defaultCallbackPort)

	clientResult, err := client.oidcClient.RegisterClient(
		ctx,
		&ssooidc.RegisterClientInput{
			ClientName:   &name,
			ClientType:   aws.String("public"),
			GrantTypes:   []string{"refresh_token", "authorization_code"},
			Scopes:       defaultScopes,
			IssuerUrl:    &client.StartUrl,
			RedirectUris: []string{redirectUrl},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("register client failed: %w", err)
	}

	credentials := &ClientCredentials{
		ClientId:     *clientResult.ClientId,
		ClientSecret: *clientResult.ClientSecret,
		ExpiresAt:    clientResult.ClientSecretExpiresAt,
	}
	client.ConfigureClient(credentials)

	return credentials, nil
}

func (client *Sso) BeginAuthorize(ctx context.Context) string {
	client.verifier = oauth2.GenerateVerifier()
	client.state = oauth2.GenerateVerifier()

	authUrl := client.oauth.AuthCodeURL(
		client.state,
		oauth2.S256ChallengeOption(client.verifier),
	)

	return authUrl
}

func (client *Sso) ListenForResponse(ctx context.Context) (*SsoTokens, error) {
	var result *ssooidc.CreateTokenOutput
	var tokenError error
	var server *http.Server

	if client.oidcClient == nil {
		client.oidcClient = ssooidc.New(ssooidc.Options{Region: client.Region})
	}

	server = &http.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", defaultCallbackPort),
		Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					w.WriteHeader(404)
					io.WriteString(w, "not found")
					return
				}
				query := r.URL.Query()
				state := query.Get("state")
				code := query.Get("code")

				if subtle.ConstantTimeCompare([]byte(client.state), []byte(state)) == 0 {
					w.WriteHeader(400)
					io.WriteString(w, "invalid state")
					return
				}
				if code == "" {
					w.WriteHeader(400)
					io.WriteString(w, "bad request")
					return
				}

				result, tokenError = client.oidcClient.CreateToken(
					r.Context(),
					&ssooidc.CreateTokenInput{
						ClientId:     &client.oauth.ClientID,
						ClientSecret: &client.oauth.ClientSecret,
						GrantType:    aws.String("authorization_code"),
						Code:         &code,
						CodeVerifier: &client.verifier,
						RedirectUri:  &client.oauth.RedirectURL,
					},
				)
				if tokenError != nil {
					log.Print(tokenError)
					w.WriteHeader(400)
					io.WriteString(w, "Bad request, please start again.")
				} else {
					w.WriteHeader(200)
					io.WriteString(w, "Success! You can close your browser now...")
				}

				go server.Shutdown(context.Background())
			},
		),
	}

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return nil, err
	}
	if tokenError != nil {
		return nil, tokenError
	}
	if result == nil {
		return nil, fmt.Errorf("waiting for the callback timed out or was cancelled")
	}

	client.tokens = SsoTokens{
		AccessToken: *result.AccessToken,
		ClientId:    client.oauth.ClientID,
		ExpiresAt:   time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix(),
	}
	if result.RefreshToken != nil {
		client.tokens.RefreshToken = *result.RefreshToken
	}

	return &client.tokens, nil
}

func (client *Sso) GetAccounts(ctx context.Context) ([]AccountInfo, error) {
	if client.tokens.AccessToken == "" {
		return nil, fmt.Errorf("not authorized")
	}
	if client.ssoClient == nil {
		client.ssoClient = sso.New(sso.Options{Region: client.Region})
	}

	var next *string
	var accounts []AccountInfo

	for hasMore := true; hasMore; hasMore = next != nil {
		response, err := client.ssoClient.ListAccounts(
			ctx,
			&sso.ListAccountsInput{
				AccessToken: &client.tokens.AccessToken,
				NextToken:   next,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("list accounts: %w", err)
		}

		next = response.NextToken

		for _, account := range response.AccountList {
			accounts = append(accounts, AccountInfo{
				AccountId:    *account.AccountId,
				AccountName:  *account.AccountName,
				EmailAddress: *account.EmailAddress,
			})
		}
	}

	return accounts, nil
}

func (client *Sso) GetAccountRoles(
	ctx context.Context,
	accountId string,
) ([]RoleInfo, error) {
	if client.tokens.AccessToken == "" {
		return nil, fmt.Errorf("not authorized")
	}
	if client.ssoClient == nil {
		client.ssoClient = sso.New(sso.Options{Region: client.Region})
	}

	var next *string
	var roles []RoleInfo

	for hasMore := true; hasMore; hasMore = next != nil {
		response, err := client.ssoClient.ListAccountRoles(
			ctx,
			&sso.ListAccountRolesInput{
				AccessToken: &client.tokens.AccessToken,
				AccountId:   &accountId,
				NextToken:   next,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("list account roles: %w", err)
		}

		next = response.NextToken

		for _, role := range response.RoleList {
			roles = append(roles, RoleInfo{
				AccountId: *role.AccountId,
				RoleName:  *role.RoleName,
			})
		}
	}

	return roles, nil
}

func (client *Sso) GetRoleCredentials(
	ctx context.Context,
	accountId string,
	roleName string,
) (*aws.Credentials, error) {
	if client.tokens.AccessToken == "" {
		return nil, fmt.Errorf("not authorized")
	}
	if client.ssoClient == nil {
		client.ssoClient = sso.New(sso.Options{Region: client.Region})
	}

	response, err := client.ssoClient.GetRoleCredentials(
		ctx,
		&sso.GetRoleCredentialsInput{
			AccessToken: &client.tokens.AccessToken,
			AccountId:   &accountId,
			RoleName:    &roleName,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("get role credentials: %w", err)
	}

	creds := &aws.Credentials{
		AccessKeyID:     *response.RoleCredentials.AccessKeyId,
		AccountID:       accountId,
		CanExpire:       true,
		Expires:         time.UnixMilli(response.RoleCredentials.Expiration),
		SecretAccessKey: *response.RoleCredentials.SecretAccessKey,
		SessionToken:    *response.RoleCredentials.SessionToken,
		Source:          "SSO",
	}
	return creds, nil
}

func (client *Sso) RefreshTokens(ctx context.Context) (*SsoTokens, error) {
	if client.oidcClient == nil {
		client.oidcClient = ssooidc.New(ssooidc.Options{Region: client.Region})
	}

	result, err := client.oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     &client.oauth.ClientID,
		ClientSecret: &client.oauth.ClientSecret,
		GrantType:    aws.String("refresh_token"),
		RefreshToken: &client.tokens.RefreshToken,
	})
	if err != nil {
		var grantErr *ssoidcTypes.InvalidGrantException
		if errors.As(err, &grantErr) {
			return nil, ErrRefreshTokenInvalid
		}
		return nil, fmt.Errorf("refresh tokens: %w", err)
	}

	client.tokens.AccessToken = *result.AccessToken
	client.tokens.ClientId = client.oauth.ClientID
	client.tokens.ExpiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix()

	if result.RefreshToken != nil {
		client.tokens.RefreshToken = *result.RefreshToken
	}

	return &client.tokens, nil
}

func (client *Sso) SetTokens(tokens *SsoTokens) {
	client.tokens = *tokens
}
