package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gordonmleigh/aws-sso/sso"
)

const (
	clientName = "aws-sso"
	// how long the user has to complete the login in their browser
	loginTimeout = 3 * time.Minute
	// cached role credentials are only used if they're valid for this long
	minCredentialLifetime = 5 * time.Minute
)

type sessionKey struct {
	region   string
	startUrl string
}

// session holds everything for one SSO session. Only the OIDC client
// registration is stored (in the keychain); the tokens and credentials are in
// memory only, so they're lost whenever the agent stops.
type session struct {
	key sessionKey
	// beforeLogin is called before logging in through the browser, which ends
	// the previous SSO session (if any), so that the user can approve it.
	// newClient is whether the client is new, so AWS will show its consent
	// page. If it fails, the login doesn't happen. s.mu is held.
	beforeLogin func(ctx context.Context, newClient bool) error
	clients     clientStore
	// openBrowser opens the login page
	openBrowser func(ctx context.Context, url string) error
	// logins is shared by all the sessions, and held while logging in through
	// the browser, because every login uses the same callback port
	logins chan struct{}

	mu            sync.Mutex
	sso           *sso.Sso
	client        *sso.ClientCredentials
	clientExpires time.Time
	// clientStored is whether the client is stored, which it is once the user
	// has logged in with it (and so given consent)
	clientStored bool
	tokens       *sso.SsoTokens
	credentials  map[string]*aws.Credentials
}

// newLoginLock returns a lock for sessions to share, so that only one logs in
// at a time.
func newLoginLock() chan struct{} {
	return make(chan struct{}, 1)
}

func newSession(key sessionKey, logins chan struct{}) *session {
	return &session{
		key:         key,
		clients:     keychainClientStore{},
		openBrowser: openBrowser,
		logins:      logins,
		credentials: map[string]*aws.Credentials{},
	}
}

func openBrowser(ctx context.Context, url string) error {
	return exec.CommandContext(ctx, "open", url).Run()
}

// ensureAuthorized logs in if needed.
func (s *session) ensureAuthorized(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorize(ctx)
}

func (s *session) listAccounts(ctx context.Context) ([]sso.AccountInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.authorize(ctx); err != nil {
		return nil, err
	}
	return s.sso.GetAccounts(ctx)
}

func (s *session) listRoles(ctx context.Context, accountId string) ([]sso.RoleInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.authorize(ctx); err != nil {
		return nil, err
	}
	return s.sso.GetAccountRoles(ctx, accountId)
}

// findAccount finds an account by ID or name.
func (s *session) findAccount(ctx context.Context, account string) (*sso.AccountInfo, error) {
	accounts, err := s.listAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts: %w", err)
	}

	match := slices.IndexFunc(accounts, func(item sso.AccountInfo) bool {
		return item.AccountId == account
	})
	if match < 0 {
		match = slices.IndexFunc(accounts, func(item sso.AccountInfo) bool {
			return item.AccountName == account
		})
	}
	if match < 0 {
		return nil, fmt.Errorf("no account found matching %s", account)
	}
	return &accounts[match], nil
}

// checkRole makes sure a role is available in an account.
func (s *session) checkRole(ctx context.Context, accountId string, roleName string) error {
	roles, err := s.listRoles(ctx, accountId)
	if err != nil {
		return fmt.Errorf("failed to get roles: %w", err)
	}
	if !slices.ContainsFunc(
		roles,
		func(role sso.RoleInfo) bool { return role.RoleName == roleName },
	) {
		return fmt.Errorf("no role found matching %s in account %s", roleName, accountId)
	}
	return nil
}

func (s *session) roleCredentials(
	ctx context.Context,
	accountId string,
	roleName string,
) (*aws.Credentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := accountId + ":" + roleName
	if creds := s.credentials[key]; creds != nil {
		if creds.Expires.After(time.Now().Add(minCredentialLifetime)) {
			log.Printf("[DEBUG] Using cached credentials (expires %s)\n", creds.Expires)
			return creds, nil
		}
		delete(s.credentials, key)
	}

	if err := s.authorize(ctx); err != nil {
		return nil, err
	}
	creds, err := s.sso.GetRoleCredentials(ctx, accountId, roleName)
	if err != nil {
		return nil, err
	}

	s.credentials[key] = creds
	return creds, nil
}

// authorize makes sure there is a valid access token, registering a client
// and logging in through the browser if needed. s.mu must be held.
func (s *session) authorize(ctx context.Context) error {
	now := time.Now()

	if s.sso == nil || s.clientExpires.Before(now.Add(24*time.Hour)) {
		s.sso = &sso.Sso{Region: s.key.region, StartUrl: s.key.startUrl}
		s.tokens = nil
		s.credentials = map[string]*aws.Credentials{}

		if err := s.initClient(ctx, now); err != nil {
			s.sso = nil
			return err
		}
	}

	if s.tokens != nil && time.Unix(s.tokens.ExpiresAt, 0).After(now.Add(5*time.Minute)) {
		return nil
	}

	if s.tokens != nil && s.tokens.RefreshToken != "" {
		log.Printf("[DEBUG] Refreshing stale access token for %s\n", s.key.startUrl)

		tokens, err := s.sso.RefreshTokens(ctx)
		if err == nil {
			s.tokens = tokens
			log.Printf(
				"[DEBUG] Obtained new access token (expires %s)\n",
				time.Unix(tokens.ExpiresAt, 0),
			)
			return nil
		}
		if errors.Is(err, sso.ErrClientInvalid) {
			// start again with a new client, which needs a login anyway
			s.discardClient()
			return s.authorize(ctx)
		}
		if !errors.Is(err, sso.ErrRefreshTokenInvalid) {
			return fmt.Errorf("authorize failure: %w", err)
		}
		log.Printf("[DEBUG] Refresh token is invalid\n")
	}

	return s.login(ctx)
}

// discardClient forgets the client, so that a new one is registered next time.
// s.mu must be held.
func (s *session) discardClient() {
	log.Printf("[DEBUG] OIDC client for %s was rejected, discarding it\n", s.key.startUrl)
	if s.clientStored {
		s.clients.delete(s.key)
	}
	s.sso = nil
}

// initClient uses the stored client if it's valid for long enough, or
// registers a new one. s.mu must be held.
func (s *session) initClient(ctx context.Context, now time.Time) error {
	if creds := s.clients.load(s.key); creds != nil {
		expires := time.Unix(creds.ExpiresAt, 0)
		if expires.After(now.Add(24 * time.Hour)) {
			s.sso.ConfigureClient(creds)
			s.client = creds
			s.clientExpires = expires
			s.clientStored = true
			log.Printf(
				"[DEBUG] Using stored OAuth2 client for %s (expires %s)\n",
				s.key.startUrl,
				expires,
			)
			return nil
		}
	}

	creds, err := s.sso.RegisterClient(ctx, clientName)
	if err != nil {
		return err
	}
	// it's stored once the user has logged in with it
	s.client = creds
	s.clientExpires = time.Unix(creds.ExpiresAt, 0)
	s.clientStored = false
	log.Printf(
		"[DEBUG] Registered new OAuth2 client for %s (expires %s)\n",
		s.key.startUrl,
		s.clientExpires,
	)
	return nil
}

func (s *session) login(ctx context.Context) error {
	// wait for any other session's login first, so that the approval prompt
	// comes straight before this login, and isn't shown if the client has gone
	select {
	case s.logins <- struct{}{}:
		defer func() { <-s.logins }()
	case <-ctx.Done():
		return ctx.Err()
	}

	if s.beforeLogin != nil {
		if err := s.beforeLogin(ctx, !s.clientStored); err != nil {
			return err
		}
	}
	// the old SSO session is over, and the credentials it gave out may be for
	// someone other than whoever logs in now
	s.tokens = nil
	s.credentials = map[string]*aws.Credentials{}

	authUrl := s.sso.BeginAuthorize(ctx)

	listenCtx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()

	// the browser is only opened once the callback listener is up
	tokens, err := s.sso.ListenForResponse(listenCtx, func() error {
		log.Printf("[INFO] opening browser to log in to %s\n", s.key.startUrl)
		if err := s.openBrowser(ctx, authUrl); err != nil {
			return fmt.Errorf("failed to open browser for login: %w", err)
		}
		return nil
	})
	if err != nil {
		// only discard the client if AWS rejected it: a timeout or a busy
		// callback port says nothing about the client, and registering a new
		// one brings back the consent page
		if errors.Is(err, sso.ErrClientInvalid) {
			s.discardClient()
		}
		return fmt.Errorf("login failed: %w", err)
	}

	s.tokens = tokens
	log.Printf("[DEBUG] Obtained new access token (expires %s)\n", time.Unix(tokens.ExpiresAt, 0))

	if !s.clientStored {
		// the user has consented to it now, so it doesn't need approving again
		s.clients.save(s.key, s.client)
		s.clientStored = true
	}
	return nil
}
