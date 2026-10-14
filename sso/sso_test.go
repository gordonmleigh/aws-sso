package sso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

// newTestSso returns an Sso whose OIDC calls go to handler, ready to log in.
func newTestSso(t *testing.T, handler http.HandlerFunc) *Sso {
	t.Helper()
	oidc := httptest.NewServer(handler)
	t.Cleanup(oidc.Close)

	client := &Sso{
		Region: "us-east-1",
		oidcClient: ssooidc.New(ssooidc.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(oidc.URL),
		}),
	}
	client.ConfigureClient(&ClientCredentials{ClientId: "id", ClientSecret: "secret"})
	client.BeginAuthorize(context.Background())
	return client
}

// callback redirects to the callback listener like the browser would.
func callback(state string) (*http.Response, error) {
	return http.Get(fmt.Sprintf(
		"http://127.0.0.1:%d/?state=%s&code=the-code",
		defaultCallbackPort,
		url.QueryEscape(state),
	))
}

func TestListenForResponse(t *testing.T) {
	client := newTestSso(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(
			w,
			`{"accessToken":"at","expiresIn":3600,"refreshToken":"rt","tokenType":"Bearer"}`,
		)
	})

	tokens, err := client.ListenForResponse(context.Background(), func() error {
		// the listener must be up by now, so the redirect can't be missed
		resp, err := callback(client.state)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("callback returned %d", resp.StatusCode)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "at" || tokens.RefreshToken != "rt" {
		t.Errorf("got tokens %+v", tokens)
	}
}

func TestListenForResponseInvalidClient(t *testing.T) {
	client := newTestSso(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Amzn-ErrorType", "InvalidClientException")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client"}`)
	})

	_, err := client.ListenForResponse(context.Background(), func() error {
		resp, err := callback(client.state)
		if err == nil {
			resp.Body.Close()
		}
		return err
	})
	if !errors.Is(err, ErrClientInvalid) {
		t.Errorf("got %v, want ErrClientInvalid", err)
	}
}

func TestListenForResponseError(t *testing.T) {
	tests := map[string]struct {
		query             string
		wantClientInvalid bool
	}{
		"denied":         {"error=access_denied&error_description=no", false},
		"client refused": {"error=unauthorized_client", true},
	}
	for name, tt := range tests {
		client := newTestSso(t, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("%s: no token should be requested", name)
		})

		// it fails straight away, rather than waiting for the timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := client.ListenForResponse(ctx, func() error {
			resp, err := http.Get(fmt.Sprintf(
				"http://127.0.0.1:%d/?state=%s&%s",
				defaultCallbackPort,
				url.QueryEscape(client.state),
				tt.query,
			))
			if err == nil {
				resp.Body.Close()
			}
			return err
		})
		cancel()

		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s: got %v, want the login error", name, err)
		}
		if errors.Is(err, ErrClientInvalid) != tt.wantClientInvalid {
			t.Errorf("%s: got %v, want ErrClientInvalid %v", name, err, tt.wantClientInvalid)
		}
	}

	// an error with the wrong state is ignored, like any other bad callback
	client := newTestSso(t, func(w http.ResponseWriter, r *http.Request) {})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := client.ListenForResponse(ctx, func() error {
		resp, err := http.Get(fmt.Sprintf(
			"http://127.0.0.1:%d/?state=wrong&error=access_denied",
			defaultCallbackPort,
		))
		if err == nil {
			resp.Body.Close()
		}
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("wrong state: got %v, want the context error", err)
	}
}

func TestListenForResponseReadyFails(t *testing.T) {
	client := newTestSso(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("no token should be requested")
	})
	errOpen := errors.New("no browser")

	_, err := client.ListenForResponse(context.Background(), func() error { return errOpen })
	if !errors.Is(err, errOpen) {
		t.Errorf("got %v, want the ready error", err)
	}
}

func TestListenForResponseCancelledDuringExchange(t *testing.T) {
	// the token exchange is still going when the login gives up
	release := make(chan struct{})
	client := newTestSso(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"accessToken":"at","expiresIn":3600,"tokenType":"Bearer"}`)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	timer := time.AfterFunc(300*time.Millisecond, func() { close(release) })
	defer timer.Stop()

	_, err := client.ListenForResponse(ctx, func() error {
		go func() {
			if resp, err := callback(client.state); err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want the context error", err)
	}
}
