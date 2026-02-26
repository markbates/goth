package google_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/google"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := googleProvider()
	a.Equal(provider.ClientKey, os.Getenv("GOOGLE_KEY"))
	a.Equal(provider.Secret, os.Getenv("GOOGLE_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := googleProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*google.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "accounts.google.com/o/oauth2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("GOOGLE_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=openid+email+profile")
	a.Contains(s.AuthURL, "access_type=offline")
}

func Test_BeginAuthWithPrompt(t *testing.T) {
	// This exists because there was a panic caused by the oauth2 package when
	// the AuthCodeOption passed was nil. This test uses it, Test_BeginAuth does
	// not, to ensure both cases are covered.
	t.Parallel()
	a := assert.New(t)

	provider := googleProvider()
	provider.SetPrompt("test", "prompts")
	session, err := provider.BeginAuth("test_state")
	s := session.(*google.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "accounts.google.com/o/oauth2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("GOOGLE_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=openid+email+profile")
	a.Contains(s.AuthURL, "access_type=offline")
	a.Contains(s.AuthURL, "prompt=test+prompts")
}

func Test_BeginAuthWithHostedDomain(t *testing.T) {
	// This exists because there was a panic caused by the oauth2 package when
	// the AuthCodeOption passed was nil. This test uses it, Test_BeginAuth does
	// not, to ensure both cases are covered.
	t.Parallel()
	a := assert.New(t)

	provider := googleProvider()
	provider.SetHostedDomain("example.com")
	session, err := provider.BeginAuth("test_state")
	s := session.(*google.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "accounts.google.com/o/oauth2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("GOOGLE_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=openid+email+profile")
	a.Contains(s.AuthURL, "access_type=offline")
	a.Contains(s.AuthURL, "hd=example.com")
}

func Test_BeginAuthWithLoginHint(t *testing.T) {
	// This exists because there was a panic caused by the oauth2 package when
	// the AuthCodeOption passed was nil. This test uses it, Test_BeginAuth does
	// not, to ensure both cases are covered.
	t.Parallel()
	a := assert.New(t)

	provider := googleProvider()
	provider.SetLoginHint("john@example.com")
	session, err := provider.BeginAuth("test_state")
	s := session.(*google.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "accounts.google.com/o/oauth2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("GOOGLE_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=openid+email+profile")
	a.Contains(s.AuthURL, "access_type=offline")
	a.Contains(s.AuthURL, "login_hint=john%40example.com")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), googleProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := googleProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://accounts.google.com/o/oauth2/auth","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*google.Session)
	a.Equal(session.AuthURL, "https://accounts.google.com/o/oauth2/auth")
	a.Equal(session.AccessToken, "1234567890")
}

func Test_UserIDHandling(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Test v2 endpoint response format (uses 'id' field)
	v2Response := `{"id":"123456789","email":"test@example.com","name":"Test User"}`
	var userV2 struct {
		ID    string `json:"id"`
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	err := json.Unmarshal([]byte(v2Response), &userV2)
	a.NoError(err)
	a.Equal("123456789", userV2.ID)
	a.Equal("", userV2.Sub)

	// Test OpenID Connect response format (uses 'sub' field)
	oidcResponse := `{"sub":"123456789","email":"test@example.com","name":"Test User"}`
	var userOIDC struct {
		ID    string `json:"id"`
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	err = json.Unmarshal([]byte(oidcResponse), &userOIDC)
	a.NoError(err)
	a.Equal("", userOIDC.ID)
	a.Equal("123456789", userOIDC.Sub)
}

func googleProvider() *google.Provider {
	return google.New(os.Getenv("GOOGLE_KEY"), os.Getenv("GOOGEL_SECRET"), "/foo")
}
