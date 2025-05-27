package quickbooks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockParams struct {
	params map[string]string
}

func (m *mockParams) Get(key string) string {
	return m.params[key]
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	s := &Session{}
	url, err := s.GetAuthURL()
	a.Error(err)
	a.Empty(url)

	s.AuthURL = "https://example.com/auth"
	url, err = s.GetAuthURL()
	a.NoError(err)
	a.Equal(url, "https://example.com/auth")
}

func Test_Authorize(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	s := &Session{}
	provider := New("client-id", "secret", "http://example.com/callback", false, ScopeAccounting)
	_, err := s.Authorize(provider, &mockParams{params: map[string]string{"code": "test_code"}})
	a.Error(err)
}

func Test_Marshal(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	s := &Session{
		AuthURL:      "https://example.com/auth",
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
		ExpiresAt:    time.Now(),
	}

	str := s.Marshal()
	a.Contains(str, "https://example.com/auth")
	a.Contains(str, "access_token")
	a.Contains(str, "refresh_token")
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	s := &Session{
		AuthURL:      "https://example.com/auth",
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
		ExpiresAt:    time.Now(),
	}

	str := s.String()
	a.Contains(str, "https://example.com/auth")
	a.Contains(str, "access_token")
	a.Contains(str, "refresh_token")
}
