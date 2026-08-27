package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"furtalk/internal/platform/cache"
	"furtalk/internal/platform/httpx"
	"furtalk/internal/platform/passkey"
	"furtalk/internal/service/identity"

	"github.com/gin-gonic/gin"
)

type passkeyLoginOptionsAdapter struct{}

func (passkeyLoginOptionsAdapter) BeginRegistration(passkey.User) (json.RawMessage, []byte, error) {
	return nil, nil, nil
}

func (passkeyLoginOptionsAdapter) FinishRegistration(passkey.User, []byte, []byte) (*passkey.Credential, error) {
	return nil, nil
}

func (passkeyLoginOptionsAdapter) BeginLogin() (json.RawMessage, []byte, error) {
	return json.RawMessage(`{"publicKey":{}}`), []byte(`{"challenge":"test-challenge"}`), nil
}

func (passkeyLoginOptionsAdapter) FinishLogin([]byte, []byte, func([]byte, []byte) (*passkey.User, error)) (*passkey.Credential, uint32, error) {
	return nil, 0, nil
}

func newPasskeyLoginOptionsService() *identity.Service {
	return identity.NewService(identity.Dependencies{
		Cache:          cache.NewMemory(10),
		PasskeyAdapter: passkeyLoginOptionsAdapter{},
	})
}

func passkeyLoginOptionsRequest(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	translator, err := NewTranslator()
	if err != nil {
		t.Fatalf("NewTranslator() error = %v", err)
	}
	router.Use(httpx.ErrorWriter(translator))
	router.POST("/options", passkeyLoginOptions(newPasskeyLoginOptionsService()))
	request := httptest.NewRequest(http.MethodPost, "/options", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestPasskeyLoginOptionsAcceptsOnlyEmptyObject(t *testing.T) {
	recorder := passkeyLoginOptionsRequest(t, `{}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestPasskeyLoginOptionsRejectsUserHandle(t *testing.T) {
	recorder := passkeyLoginOptionsRequest(t, `{"user_handle":"1"}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestPasskeyLoginOptionsRejectsNonObjectBodies(t *testing.T) {
	for _, body := range []string{"null", "[]"} {
		t.Run(body, func(t *testing.T) {
			recorder := passkeyLoginOptionsRequest(t, body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}
