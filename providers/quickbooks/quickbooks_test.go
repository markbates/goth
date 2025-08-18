package quickbooks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := New("client-id", "secret", "http://example.com/callback", false, ScopeAccounting)
	a.Equal(provider.ClientId(), "client-id")
	a.Equal(provider.Secret(), "secret")
	a.Equal(provider.RedirectURL(), "http://example.com/callback")
	a.Equal(provider.Name(), "quickbooks")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), New("", "", "", false))
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := New("client-id", "secret", "http://example.com/callback", false, ScopeAccounting)
	session, err := provider.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "appcenter.intuit.com/connect/oauth2")
	a.Contains(s.AuthURL, "client_id=client-id")
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=com.intuit.quickbooks.accounting")
}

func Test_FetchUser(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.Equal(r.Header.Get("Authorization"), "Bearer access_token")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":            "user123",
			"email":          "user@example.com",
			"email_verified": true,
			"name":           "John Doe",
			"given_name":     "John",
			"family_name":    "Doe",
		})
	}))
	defer ts.Close()

	provider := New("client-id", "secret", "http://example.com/callback", false, ScopeAccounting)
	provider.userInfoURL = ts.URL
	session := &Session{
		AccessToken: "access_token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	user, err := provider.FetchUser(session)
	a.NoError(err)
	a.Equal(user.UserID, "user123")
	a.Equal(user.Email, "user@example.com")
	a.Equal(user.Name, "John Doe")
	a.Equal(user.FirstName, "John")
	a.Equal(user.LastName, "Doe")
	a.Equal(user.AccessToken, "access_token")
}

func Test_RefreshToken(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.Equal(r.Method, "POST")
		a.Equal(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new_access_token",
			"token_type":    "bearer",
			"expires_in":    3600,
			"refresh_token": "new_refresh_token",
		})
	}))
	defer ts.Close()

	provider := New("client-id", "secret", "http://example.com/callback", false, ScopeAccounting)
	provider.config.Endpoint.TokenURL = ts.URL

	token, err := provider.RefreshToken("refresh_token")
	a.NoError(err)
	a.NotNil(token)
	a.Equal(token.AccessToken, "new_access_token")
	a.Equal(token.RefreshToken, "new_refresh_token")
	a.True(token.Expiry.After(time.Now()))
}

func Test_RefreshTokenAvailable(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := New("client-id", "secret", "http://example.com/callback", false, ScopeAccounting)
	a.True(provider.RefreshTokenAvailable())
}
