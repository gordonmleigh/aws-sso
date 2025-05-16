package store

import (
	"encoding/json"
	"errors"
	"fmt"

	"propulsionworks.io/aws-sso/keychain"
	"propulsionworks.io/aws-sso/sso"
)

const (
	authTokens        = "auth-tokens"
	clientCredentials = "oauth-client"
	roleCredentials   = "role-credentials"
)

type AuthStore struct {
	AppId string
}

func (store *AuthStore) GetClientCredentials(name string) (*sso.ClientCredentials, error) {
	result := &sso.ClientCredentials{}
	if err := store.getJsonValue(clientCredentials, name, result); err != nil {
		if errors.Is(err, keychain.ErrSecItemNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return result, nil
}

func (store *AuthStore) GetRoleCredentials(accountId string, roleName string) (*sso.RoleCredentials, error) {
	result := &sso.RoleCredentials{}

	err := store.getJsonValue(
		roleCredentials,
		accountId+":"+roleName,
		result,
	)
	if err != nil {
		if errors.Is(err, keychain.ErrSecItemNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return result, nil
}

func (store *AuthStore) GetTokens(name string) (*sso.SsoTokens, error) {
	result := &sso.SsoTokens{}
	if err := store.getJsonValue(authTokens, name, result); err != nil {
		if errors.Is(err, keychain.ErrSecItemNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return result, nil
}

func (store *AuthStore) SetClientCredentials(name string, credentials *sso.ClientCredentials) error {
	return store.setJsonValue(clientCredentials, name, credentials)
}

func (store *AuthStore) SetRoleCredentials(accountId string, roleName string, credentials *sso.RoleCredentials) error {
	return store.setJsonValue(roleCredentials, accountId+":"+roleName, credentials)
}

func (store *AuthStore) SetTokens(name string, tokens *sso.SsoTokens) error {
	return store.setJsonValue(authTokens, name, tokens)
}

func (store *AuthStore) getJsonValue(valueType string, name string, v any) error {
	key := fmt.Sprintf("%s:%s", valueType, name)

	value, err := keychain.GetKeychainItem(store.AppId, key)
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(value), v)
}

func (store *AuthStore) setJsonValue(valueType string, name string, v any) error {
	key := fmt.Sprintf("%s:%s", valueType, name)

	value, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return keychain.SetKeychainItem(store.AppId, key, string(value))
}
