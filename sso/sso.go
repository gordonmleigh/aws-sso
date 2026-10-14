package sso

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
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
	// ErrClientInvalid means the OIDC client registration was rejected, so a
	// new one is needed.
	ErrClientInvalid = errors.New("OIDC client is invalid")
)

// clientError wraps err with ErrClientInvalid if AWS rejected the client.
func clientError(err error) error {
	var invalidClient *ssoidcTypes.InvalidClientException
	var unauthorizedClient *ssoidcTypes.UnauthorizedClientException
	if errors.As(err, &invalidClient) || errors.As(err, &unauthorizedClient) {
		return fmt.Errorf("%w: %w", ErrClientInvalid, err)
	}
	return err
}

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
	AccountId   string
	AccountName string
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

// ListenForResponse waits for the browser to be redirected back after a login,
// and exchanges the code for tokens. ready is called once the callback
// listener is up, to open the browser, so that the redirect can't arrive
// before anything is listening for it.
func (client *Sso) ListenForResponse(ctx context.Context, ready func() error) (*SsoTokens, error) {
	if client.oidcClient == nil {
		client.oidcClient = ssooidc.New(ssooidc.Options{Region: client.Region})
	}

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", defaultCallbackPort))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for the login callback: %w", err)
	}

	type outcome struct {
		result *ssooidc.CreateTokenOutput
		err    error
	}
	// only the first valid callback is used; the buffer means the handler
	// never waits for it to be read
	done := make(chan outcome, 1)
	var handled atomic.Bool

	server := &http.Server{
		Handler: http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				query := r.URL.Query()
				state := query.Get("state")
				code := query.Get("code")

				if subtle.ConstantTimeCompare([]byte(client.state), []byte(state)) == 0 {
					http.Error(w, "invalid state", http.StatusBadRequest)
					return
				}
				// the login was refused or failed (e.g. the user denied the
				// consent page), so stop waiting for it
				if errCode := query.Get("error"); errCode != "" {
					if !handled.CompareAndSwap(false, true) {
						http.Error(w, "already logged in", http.StatusBadRequest)
						return
					}
					err := fmt.Errorf("login failed in the browser: %s", errCode)
					if description := query.Get("error_description"); description != "" {
						err = fmt.Errorf("%w (%s)", err, description)
					}
					if errCode == "unauthorized_client" || errCode == "invalid_client" {
						err = fmt.Errorf("%w: %w", ErrClientInvalid, err)
					}
					http.Error(
						w,
						"Login failed, you can close your browser now.",
						http.StatusBadRequest,
					)
					done <- outcome{nil, err}
					return
				}
				if code == "" {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				if !handled.CompareAndSwap(false, true) {
					http.Error(w, "already logged in", http.StatusBadRequest)
					return
				}

				result, err := client.oidcClient.CreateToken(
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
				if err != nil {
					http.Error(w, "Bad request, please start again.", http.StatusBadRequest)
				} else {
					_, _ = io.WriteString(w, "Success! You can close your browser now...")
				}
				done <- outcome{result, err}
			},
		),
	}

	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := ready(); err != nil {
		return nil, err
	}

	var result *ssooidc.CreateTokenOutput
	select {
	case o := <-done:
		if o.err != nil {
			return nil, clientError(o.err)
		}
		result = o.result
	case err := <-served:
		return nil, fmt.Errorf("login callback server failed: %w", err)
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for the callback timed out or was cancelled: %w", ctx.Err())
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
				AccountId:   *account.AccountId,
				AccountName: *account.AccountName,
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
		return nil, fmt.Errorf("refresh tokens: %w", clientError(err))
	}

	client.tokens.AccessToken = *result.AccessToken
	client.tokens.ClientId = client.oauth.ClientID
	client.tokens.ExpiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).Unix()

	if result.RefreshToken != nil {
		client.tokens.RefreshToken = *result.RefreshToken
	}

	return &client.tokens, nil
}
