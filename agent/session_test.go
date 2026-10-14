package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gordonmleigh/aws-sso/sso"
)

// fakeClientStore is a clientStore in memory.
type fakeClientStore struct {
	clients map[sessionKey]*sso.ClientCredentials
	saves   int
}

func (f *fakeClientStore) load(key sessionKey) *sso.ClientCredentials {
	return f.clients[key]
}

func (f *fakeClientStore) save(key sessionKey, creds *sso.ClientCredentials) {
	f.clients[key] = creds
	f.saves++
}

func (f *fakeClientStore) delete(key sessionKey) {
	delete(f.clients, key)
}

func TestStoredClientIsUsed(t *testing.T) {
	key := sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"}
	stored := &sso.ClientCredentials{
		ClientId:     "stored",
		ClientSecret: "secret",
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour).Unix(),
	}
	store := &fakeClientStore{clients: map[sessionKey]*sso.ClientCredentials{key: stored}}

	s := newSession(key, newLoginLock())
	s.clients = store
	s.sso = &sso.Sso{Region: key.region, StartUrl: key.startUrl}

	// a stored client that's valid for long enough is used without registering
	if err := s.initClient(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if !s.clientStored || s.client != stored {
		t.Errorf("stored client wasn't used: stored %v, client %+v", s.clientStored, s.client)
	}
}

func TestLoginApproval(t *testing.T) {
	key := sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"}
	errStop := errors.New("stop before opening the browser")

	tests := map[string]struct {
		stored        bool
		wantNewClient bool
	}{
		"new client":    {stored: false, wantNewClient: true},
		"stored client": {stored: true, wantNewClient: false},
	}
	for name, tt := range tests {
		store := &fakeClientStore{clients: map[sessionKey]*sso.ClientCredentials{}}
		s := newSession(key, newLoginLock())
		s.clients = store
		s.sso = &sso.Sso{Region: key.region, StartUrl: key.startUrl}
		s.client = &sso.ClientCredentials{ClientId: "client"}
		s.clientStored = tt.stored

		var newClient []bool
		s.beforeLogin = func(ctx context.Context, n bool) error {
			newClient = append(newClient, n)
			// denied, or stopped before the browser opens
			return errStop
		}

		if err := s.login(context.Background()); !errors.Is(err, errStop) {
			t.Errorf("%s: got %v, want the beforeLogin error", name, err)
		}
		if len(newClient) != 1 || newClient[0] != tt.wantNewClient {
			t.Errorf(
				"%s: beforeLogin got newClient %v, want [%v]",
				name,
				newClient,
				tt.wantNewClient,
			)
		}
		if store.saves != 0 || s.clientStored != tt.stored {
			t.Errorf(
				"%s: a login that didn't happen shouldn't store the client (saves %d, stored %v)",
				name,
				store.saves,
				s.clientStored,
			)
		}
	}
}

func TestLoginWaitsForOtherLogins(t *testing.T) {
	logins := newLoginLock()
	s := newSession(
		sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"},
		logins,
	)
	called := false
	s.beforeLogin = func(ctx context.Context, newClient bool) error {
		called = true
		return nil
	}

	// another session is logging in
	logins <- struct{}{}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.login(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want the context error", err)
	}
	if called {
		t.Error("the login was approved while another was in progress")
	}
}

func TestDiscardClient(t *testing.T) {
	key := sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"}
	stored := &sso.ClientCredentials{ClientId: "stored"}
	store := &fakeClientStore{clients: map[sessionKey]*sso.ClientCredentials{key: stored}}

	s := newSession(key, newLoginLock())
	s.clients = store
	s.sso = &sso.Sso{Region: key.region, StartUrl: key.startUrl}
	s.client = stored
	s.clientStored = true

	s.discardClient()
	if store.clients[key] != nil {
		t.Error("the rejected client is still stored")
	}
	if s.sso != nil {
		t.Error("the rejected client is still in use")
	}
}

func TestLoginForgetsCredentials(t *testing.T) {
	key := sessionKey{region: "eu-central-1", startUrl: "https://work.awsapps.com/start"}
	errDenied := errors.New("denied")
	errNoBrowser := errors.New("no browser")

	tests := map[string]struct {
		beforeLogin error
		wantCached  bool
	}{
		// the old session carries on if the login doesn't happen
		"login denied": {beforeLogin: errDenied, wantCached: true},
		"login starts": {wantCached: false},
	}
	for name, tt := range tests {
		s := newSession(key, newLoginLock())
		s.clients = &fakeClientStore{clients: map[sessionKey]*sso.ClientCredentials{}}
		s.sso = &sso.Sso{Region: key.region, StartUrl: key.startUrl}
		s.client = &sso.ClientCredentials{ClientId: "client"}
		s.clientStored = true
		s.credentials["123:Admin"] = &aws.Credentials{AccessKeyID: "old"}
		s.beforeLogin = func(ctx context.Context, newClient bool) error { return tt.beforeLogin }
		s.openBrowser = func(ctx context.Context, url string) error { return errNoBrowser }

		if err := s.login(context.Background()); err == nil {
			t.Fatalf("%s: login succeeded", name)
		}
		if cached := s.credentials["123:Admin"] != nil; cached != tt.wantCached {
			t.Errorf("%s: credentials cached %v, want %v", name, cached, tt.wantCached)
		}
	}
}
