package agent

import (
	"encoding/json/v2"
	"errors"
	"log"

	"github.com/gordonmleigh/aws-sso/darwin"
	"github.com/gordonmleigh/aws-sso/sso"
)

// The OIDC client registration for each SSO session is kept in the keychain
// once the user has logged in with it, so that logins keep using the same
// client. AWS only shows its consent page for a new client, so then it only
// appears for the first login, and one appearing later stands out. The
// registration isn't much use without the user logging in, and nothing else
// (tokens or credentials) is stored.

// clientStore stores OIDC client registrations.
type clientStore interface {
	load(key sessionKey) *sso.ClientCredentials
	save(key sessionKey, creds *sso.ClientCredentials)
	delete(key sessionKey)
}

type keychainClientStore struct{}

func clientItemKey(key sessionKey) string {
	return "oauth-client:" + key.region + ":" + key.startUrl
}

// load returns the stored client for an SSO session, or nil.
func (keychainClientStore) load(key sessionKey) *sso.ClientCredentials {
	value, err := darwin.GetKeychainItem(Label, clientItemKey(key))
	if errors.Is(err, darwin.ErrKeychainItemNotFound) {
		return nil
	}
	if err != nil {
		log.Printf("[WARN] failed to load the OIDC client from the keychain: %v\n", err)
		return nil
	}

	var creds sso.ClientCredentials
	if err := json.Unmarshal([]byte(value), &creds); err != nil {
		log.Printf("[WARN] ignoring invalid OIDC client in the keychain: %v\n", err)
		return nil
	}
	return &creds
}

func (keychainClientStore) save(key sessionKey, creds *sso.ClientCredentials) {
	value, err := json.Marshal(creds)
	if err == nil {
		err = darwin.SetKeychainItem(Label, clientItemKey(key), string(value))
	}
	if err != nil {
		log.Printf("[WARN] failed to save the OIDC client in the keychain: %v\n", err)
		return
	}
	log.Printf("[DEBUG] Stored OAuth2 client for %s in the keychain\n", key.startUrl)
}

func (keychainClientStore) delete(key sessionKey) {
	if err := darwin.DeleteKeychainItem(Label, clientItemKey(key)); err != nil {
		log.Printf("[WARN] failed to remove the OIDC client from the keychain: %v\n", err)
	}
}
