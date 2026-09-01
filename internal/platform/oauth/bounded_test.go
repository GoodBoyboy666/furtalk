package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingBody struct {
	reader   *bytes.Reader
	read     int
	closed   bool
	readCall int
}

func (b *trackingBody) Read(p []byte) (int, error) {
	b.readCall++
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

func responseWithBody(body *trackingBody, contentLength int64) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        make(http.Header),
		Body:          body,
		ContentLength: contentLength,
		Request:       &http.Request{},
	}
}

func TestBoundedTransportRejectsDeclaredOversizeAndClosesBody(t *testing.T) {
	body := &trackingBody{reader: bytes.NewReader([]byte("not read"))}
	client := boundedClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return responseWithBody(body, maxOAuthResponseBytes+1), nil
	})}, 0)

	_, err := client.Do(mustRequest(t))
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("declared oversized response error = %v, want ErrResponseTooLarge", err)
	}
	if !body.closed {
		t.Fatal("declared oversized response body must be closed")
	}
	if body.read != 0 {
		t.Fatalf("declared oversized response read %d bytes before rejection, want 0", body.read)
	}
}

func TestBoundedTransportRejectsChunkedOversizeAfterOneByteBeyondLimit(t *testing.T) {
	body := &trackingBody{reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, int(maxOAuthResponseBytes)+4096))}
	client := boundedClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return responseWithBody(body, -1), nil
	})}, 0)

	_, err := client.Do(mustRequest(t))
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("chunked oversized response error = %v, want ErrResponseTooLarge", err)
	}
	if !body.closed {
		t.Fatal("chunked oversized response body must be closed")
	}
	if body.read > int(maxOAuthResponseBytes)+1 {
		t.Fatalf("chunked oversized response read %d bytes, want at most %d", body.read, maxOAuthResponseBytes+1)
	}
}

func TestBoundedTransportAcceptsExactLimitAndReplaysBody(t *testing.T) {
	want := bytes.Repeat([]byte{'a'}, int(maxOAuthResponseBytes))
	body := &trackingBody{reader: bytes.NewReader(want)}
	client := boundedClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return responseWithBody(body, maxOAuthResponseBytes), nil
	})}, 0)

	resp, err := client.Do(mustRequest(t))
	if err != nil {
		t.Fatalf("exact-limit response: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read exact-limit response: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("exact-limit body changed: got %d bytes, want %d", len(got), len(want))
	}
	if resp.ContentLength != maxOAuthResponseBytes {
		t.Fatalf("replayed ContentLength = %d, want %d", resp.ContentLength, maxOAuthResponseBytes)
	}
	if !body.closed {
		t.Fatal("accepted response must close the upstream body after buffering")
	}
}

func TestBoundedClientPreservesInjectedTransportAndTimeout(t *testing.T) {
	called := false
	base := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			body := &trackingBody{reader: bytes.NewReader([]byte(`{"ok":true}`))}
			return responseWithBody(body, int64(len(`{"ok":true}`))), nil
		}),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	client := boundedClient(base, 3*time.Second)
	if client == base {
		t.Fatal("bounded client must clone the injected client")
	}
	if client.Timeout != 3*time.Second {
		t.Fatalf("bounded client timeout = %s, want 3s", client.Timeout)
	}
	if client.CheckRedirect == nil {
		t.Fatal("bounded client must preserve CheckRedirect")
	}
	resp, err := client.Do(mustRequest(t))
	if err != nil {
		t.Fatalf("request through bounded injected transport: %v", err)
	}
	_ = resp.Body.Close()
	if !called {
		t.Fatal("bounded client did not invoke the injected transport")
	}
}

func TestBoundedClientAppliesSafeFallbackForNonPositiveTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		base := &http.Client{Timeout: 2 * time.Minute}
		client := boundedClient(base, timeout)
		if client.Timeout != defaultOAuthClientTimeout {
			t.Fatalf("timeout %s produced client timeout %s, want %s", timeout, client.Timeout, defaultOAuthClientTimeout)
		}
		if client == base {
			t.Fatal("bounded client must clone the injected client")
		}
	}
}

func TestOIDCDiscoveryPreservesOversizedResponseCategory(t *testing.T) {
	body := &trackingBody{reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, int(maxOAuthResponseBytes)+1))}
	client := boundedClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return responseWithBody(body, -1), nil
	})}, 0)
	p, err := newOIDCProvider(Config{ProviderKey: "custom", IssuerURL: "https://idp.example", HTTPClient: client}, client)
	if err != nil {
		t.Fatalf("new OIDC provider: %v", err)
	}
	_, err = p.BuildAuthURL(context.Background(), AuthorizationRequest{State: "state", RedirectURI: "https://app.example/callback"})
	if !IsResponseTooLarge(err) {
		t.Fatalf("OIDC discovery error = %v, want oversized category", err)
	}
}

func TestGitHubExchangePreservesOversizedResponseCategory(t *testing.T) {
	body := &trackingBody{reader: bytes.NewReader([]byte("not read"))}
	client := boundedClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return responseWithBody(body, maxOAuthResponseBytes+1), nil
	})}, 0)
	p := newGitHubProvider(Config{
		ProviderKey:  "github",
		ClientID:     "client",
		ClientSecret: "secret",
		AuthURL:      "https://github.example/authorize",
		TokenURL:     "https://github.example/token",
	}, client)
	_, err := p.Exchange(context.Background(), ExchangeRequest{Code: "code", RedirectURI: "https://app.example/callback"})
	if !IsResponseTooLarge(err) {
		t.Fatalf("GitHub exchange error = %v, want oversized category", err)
	}
}

func TestOIDCJWKSAndUserInfoPreserveOversizedResponseCategory(t *testing.T) {
	t.Run("jwks", func(t *testing.T) {
		body := &trackingBody{reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, int(maxOAuthResponseBytes)+1))}
		client := boundedClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return responseWithBody(body, -1), nil
		})}, 0)
		keySet := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), "https://idp.example/jwks")
		jwt := strings.Join([]string{
			base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"key"}`)),
			base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`)),
			base64.RawURLEncoding.EncodeToString([]byte("signature")),
		}, ".")
		_, err := keySet.VerifySignature(context.Background(), jwt)
		if !IsResponseTooLarge(err) {
			t.Fatalf("OIDC JWKS error = %v, want oversized category", err)
		}
	})

	t.Run("userinfo", func(t *testing.T) {
		body := &trackingBody{reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, int(maxOAuthResponseBytes)+1))}
		client := boundedClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return responseWithBody(body, -1), nil
		})}, 0)
		provider := (&oidc.ProviderConfig{
			IssuerURL:   "https://idp.example",
			UserInfoURL: "https://idp.example/userinfo",
		}).NewProvider(oidc.ClientContext(context.Background(), client))
		_, err := provider.UserInfo(oidc.ClientContext(context.Background(), client), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "token"}))
		if !IsResponseTooLarge(err) {
			t.Fatalf("OIDC userinfo error = %v, want oversized category", err)
		}
	})
}

func mustRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://idp.example/resource", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}
