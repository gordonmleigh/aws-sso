package authorizer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"slices"
	"time"

	"propulsionworks.io/aws-sso/keychain"
	"propulsionworks.io/aws-sso/sso"
	"propulsionworks.io/aws-sso/store"
)

const (
	DefaultAppId      = "io.propulsionworks.aws-sso"
	DefaultClientName = "PropulsionWorks AWS SSO"
)

type Authorizer struct {
	AppId       string
	ClientName  string
	ProfileName string
	Region      string
	StartUrl    string

	store *store.AuthStore
	sso   *sso.Sso
}

func (auth *Authorizer) Authorize(ctx context.Context) error {
	auth.init()

	newClient, err := auth.InitializeClient(ctx)
	if err != nil {
		return err
	}

	var tokens *sso.SsoTokens
	if !newClient {
		if tokens, err = auth.store.GetTokens(auth.ProfileName); err != nil {
			// it isn't crucial that we get the tokens
			log.Printf("[WARN] %v\n", err)
		}
		// make sure the stored tokens are relevant
		if tokens != nil && tokens.ClientId == auth.sso.ClientId() {
			expires := time.Unix(tokens.ExpiresAt, 0).String()
			log.Printf("[DEBUG] Have cached access token (expires %s)\n", expires)
			auth.sso.SetTokens(tokens)
		} else {
			tokens = nil
		}
	}

	expiryDeadline := time.Now().Add(5 * time.Minute).Unix()
	if tokens != nil && tokens.ExpiresAt >= expiryDeadline {
		return nil
	}

	if tokens != nil && tokens.RefreshToken != "" {
		log.Print("[DEBUG] Refreshing stale access token...\n")

		// tokens are old, try refreshing
		tokens, err = auth.sso.RefreshTokens(ctx)

		if err == nil {
			if err = auth.store.SetTokens(auth.ProfileName, tokens); err != nil {
				log.Printf("[WARN] %v", err)
			}

			expires := time.Unix(tokens.ExpiresAt, 0).String()
			log.Printf("[DEBUG] Obtained new access token (expires %s)\n", expires)
			return nil
		}
		if errors.Is(err, sso.ErrRefreshTokenInvalid) {
			log.Printf("[DEBUG] Refresh token is invalid")
		} else {
			return fmt.Errorf("authorize failure: %w", err)
		}
	}

	return auth.Reauthorize(ctx)
}

func (auth *Authorizer) GetRoleCredentials(
	ctx context.Context,
	accountId string,
	roleName string,
	ttlMinutes int,
) (*sso.RoleCredentials, error) {
	auth.init()

	// can skip lookup by passing ttlMinutes = -1
	if ttlMinutes >= 0 {
		creds, err := auth.store.GetRoleCredentials(accountId, roleName)
		if err != nil {
			log.Printf("[WARN] %v", err)
		}

		threshold := time.Now().Add(time.Duration(ttlMinutes) * time.Minute).Unix()
		if creds != nil && creds.Expiration >= threshold {
			expires := time.Unix(creds.Expiration, 0).String()
			log.Printf("[DEBUG] Credentials are stale (expires %s)\n", expires)
			return creds, nil
		}
	}

	accountName := accountId

	accounts, err := auth.sso.GetAccounts(ctx)
	if err != nil {
		log.Printf("[WARN] Failed to get accounts: %v", err)
	} else {
		match := slices.IndexFunc(accounts, func(item sso.AccountInfo) bool {
			return item.AccountId == accountId
		})
		if match >= 0 {
			account := accounts[match]

			accountName = fmt.Sprintf(
				"%s (%s, %s)",
				account.AccountName,
				account.AccountId,
				account.EmailAddress,
			)
		}
	}

	procName := keychain.GetParentProcessName()
	authReason := fmt.Sprintf(
		"give role credentials for account %s, role \"%s\" to process \"%s\"",
		accountName,
		roleName,
		procName,
	)

	err = keychain.RequestUserAuthorization(authReason)
	if err != nil {
		return nil, fmt.Errorf("failed to get user consent: %w", err)
	}

	creds, err := auth.sso.GetRoleCredentials(ctx, accountId, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get role credentials: %w", err)
	}

	if err = auth.store.SetRoleCredentials(accountId, roleName, creds); err != nil {
		// just log and continue because it's not critical that we save
		log.Printf("[WARN] %v\n", err)
	}
	return creds, nil
}

func (auth *Authorizer) InitializeClient(ctx context.Context) (bool, error) {
	auth.init()

	creds, err := auth.store.GetClientCredentials(auth.ProfileName)
	if err != nil {
		log.Printf("[WARN] %v\n", err)
	}

	if creds == nil {
		log.Printf("[DEBUG] No existing client credentials\n")
	} else {
		expires := time.Unix(creds.ExpiresAt, 0).String()
		log.Printf("[DEBUG] Found existing client credentials (expires %s)\n", expires)
	}

	if creds != nil && creds.ExpiresAt > time.Now().Add(24*time.Hour).Unix() {
		auth.sso.ConfigureClient(creds)
		return false, nil
	}

	// credentials are invalid, register again
	return true, auth.ReinitializeClient(ctx)
}

func (auth *Authorizer) Reauthorize(ctx context.Context) error {
	auth.init()

	authUrl := auth.sso.BeginAuthorize(ctx)
	log.Printf("[DEBUG] Opening browser to complete authorization: %s\n", authUrl)

	err := exec.CommandContext(ctx, "open", authUrl).Start()
	if err != nil {
		log.Printf("[WARN] open failed: %v\n", err)
		log.Printf("Please open link manually: %s\n", authUrl)
	}

	listenCtx, cancelListen := context.WithDeadline(
		ctx,
		time.Now().Add(3*time.Minute),
	)
	defer cancelListen()

	tokens, err := auth.sso.ListenForResponse(listenCtx)
	if err != nil {
		return fmt.Errorf("reauthorize: listen failed: %w", err)
	}

	expires := time.Unix(tokens.ExpiresAt, 0).String()
	log.Printf("[DEBUG] Obtained new access token (expires %s)\n", expires)

	return auth.store.SetTokens(auth.ProfileName, tokens)
}

func (auth *Authorizer) ReinitializeClient(ctx context.Context) error {
	auth.init()

	creds, err := auth.sso.RegisterClient(ctx, auth.ClientName)
	if err != nil {
		return err
	}
	expires := time.Unix(creds.ExpiresAt, 0).String()
	log.Printf("[DEBUG] Registered new OAuth2 client (expires %s)\n", expires)

	return auth.store.SetClientCredentials(auth.ProfileName, creds)
}

func (auth *Authorizer) Sso() *sso.Sso {
	auth.init()
	return auth.sso
}

func (auth *Authorizer) init() {
	if auth.AppId == "" {
		auth.AppId = DefaultAppId
	}
	if auth.ClientName == "" {
		auth.ClientName = DefaultClientName
	}
	if auth.ProfileName == "" {
		auth.ProfileName = auth.StartUrl
	}
	if auth.Region == "" {
		panic(fmt.Errorf("must provide Region"))
	}
	if auth.StartUrl == "" {
		panic(fmt.Errorf("must provide StartUrl"))
	}
	if auth.store == nil {
		auth.store = &store.AuthStore{
			AppId: auth.AppId,
		}
	}
	if auth.sso == nil {
		auth.sso = &sso.Sso{
			Region:   auth.Region,
			StartUrl: auth.StartUrl,
		}
	}
}
