package openidConnect

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"fmt"
	"github.com/markbates/goth"
	"net/http/httptest"
	"net/http"
)

var (
	server *httptest.Server
)

func init() {
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// return the value of Google's setup at https://accounts.google.com/.well-known/openid-configuration
		fmt.Fprintln(w, "{ \"issuer\": \"https://accounts.google.com\", \"authorization_endpoint\": \"https://accounts.google.com/o/oauth2/v2/auth\", \"token_endpoint\": \"https://www.googleapis.com/oauth2/v4/token\", \"userinfo_endpoint\": \"https://www.googleapis.com/oauth2/v3/userinfo\", \"revocation_endpoint\": \"https://accounts.google.com/o/oauth2/revoke\", \"jwks_uri\": \"https://www.googleapis.com/oauth2/v3/certs\", \"response_types_supported\": [ \"code\", \"token\", \"id_token\", \"code token\", \"code id_token\", \"token id_token\", \"code token id_token\", \"none\" ], \"subject_types_supported\": [ \"public\" ], \"id_token_signing_alg_values_supported\": [ \"RS256\" ], \"scopes_supported\": [ \"openid\", \"email\", \"profile\" ], \"token_endpoint_auth_methods_supported\": [ \"client_secret_post\", \"client_secret_basic\" ], \"claims_supported\": [ \"aud\", \"email\", \"email_verified\", \"exp\", \"family_name\", \"given_name\", \"iat\", \"iss\", \"locale\", \"name\", \"picture\", \"sub\" ], \"code_challenge_methods_supported\": [ \"plain\", \"S256\" ] }")
	}))
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	a.Equal(os.Getenv("OPENID_CONNECT_KEY"), provider.ClientKey)
	a.Equal(os.Getenv("OPENID_CONNECT_SECRET"), provider.Secret)
	a.Equal("http://localhost/foo", provider.CallbackURL)

	a.Equal("https://accounts.google.com", provider.openIDConfig.Issuer)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", provider.openIDConfig.AuthEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v4/token", provider.openIDConfig.TokenEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v3/userinfo", provider.openIDConfig.UserInfoEndpoint)
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("OPENID_CONNECT_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "redirect_uri=http%3A%2F%2Flocalhost%2Ffoo")
	a.Contains(s.AuthURL, "scope=openid")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), openidConnectProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://accounts.google.com/o/oauth2/v2/auth","AccessToken":"1234567890","IDToken":"abc"}`)
	a.NoError(err)
	session := s.(*Session)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", session.AuthURL)
	a.Equal("1234567890", session.AccessToken)
	a.Equal("abc", session.IDToken)
}

func openidConnectProvider() *Provider {
	provider, _ := New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost/foo", server.URL)
	return provider
}
