package openidConnect

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

var (
	server *httptest.Server
)

func init() {
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// return the value of Google's setup at https://accounts.google.com/.well-known/openid-configuration
		_, _ = fmt.Fprintln(w, "{ \"issuer\": \"https://accounts.google.com\", \"authorization_endpoint\": \"https://accounts.google.com/o/oauth2/v2/auth\", \"token_endpoint\": \"https://www.googleapis.com/oauth2/v4/token\", \"userinfo_endpoint\": \"https://www.googleapis.com/oauth2/v3/userinfo\", \"revocation_endpoint\": \"https://accounts.google.com/o/oauth2/revoke\", \"jwks_uri\": \"https://www.googleapis.com/oauth2/v3/certs\", \"response_types_supported\": [ \"code\", \"token\", \"id_token\", \"code token\", \"code id_token\", \"token id_token\", \"code token id_token\", \"none\" ], \"subject_types_supported\": [ \"public\" ], \"id_token_signing_alg_values_supported\": [ \"RS256\" ], \"scopes_supported\": [ \"openid\", \"email\", \"profile\" ], \"token_endpoint_auth_methods_supported\": [ \"client_secret_post\", \"client_secret_basic\" ], \"claims_supported\": [ \"aud\", \"email\", \"email_verified\", \"exp\", \"family_name\", \"given_name\", \"iat\", \"iss\", \"locale\", \"name\", \"picture\", \"sub\" ], \"code_challenge_methods_supported\": [ \"plain\", \"S256\" ] }")
	}))
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	a.Equal(os.Getenv("OPENID_CONNECT_KEY"), provider.ClientKey)
	a.Equal(os.Getenv("OPENID_CONNECT_SECRET"), provider.Secret)
	a.Equal("http://localhost/foo", provider.CallbackURL)

	a.Equal("https://accounts.google.com", provider.OpenIDConfig.Issuer)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", provider.OpenIDConfig.AuthEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v4/token", provider.OpenIDConfig.TokenEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v3/userinfo", provider.OpenIDConfig.UserInfoEndpoint)
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, _ := NewCustomisedURL(
		os.Getenv("OPENID_CONNECT_KEY"),
		os.Getenv("OPENID_CONNECT_SECRET"),
		"http://localhost/foo",
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://www.googleapis.com/oauth2/v4/token",
		"https://accounts.google.com",
		"https://www.googleapis.com/oauth2/v3/userinfo",
		"",
		server.URL,
	)
	a.Equal(os.Getenv("OPENID_CONNECT_KEY"), provider.ClientKey)
	a.Equal(os.Getenv("OPENID_CONNECT_SECRET"), provider.Secret)
	a.Equal("http://localhost/foo", provider.CallbackURL)

	a.Equal("https://accounts.google.com", provider.OpenIDConfig.Issuer)
	a.Equal("https://accounts.google.com/o/oauth2/v2/auth", provider.OpenIDConfig.AuthEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v4/token", provider.OpenIDConfig.TokenEndpoint)
	a.Equal("https://www.googleapis.com/oauth2/v3/userinfo", provider.OpenIDConfig.UserInfoEndpoint)
	a.Equal("", provider.OpenIDConfig.EndSessionEndpoint)
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

func Test_BeginAuth_AuthCodeOptions(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	provider.SetAuthCodeOptions(map[string]string{"domain_hint": "test_domain.com", "prompt": "none"})
	session, err := provider.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://accounts.google.com/o/oauth2/v2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("OPENID_CONNECT_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "redirect_uri=http%3A%2F%2Flocalhost%2Ffoo")
	a.Contains(s.AuthURL, "scope=openid")
	a.Contains(s.AuthURL, "domain_hint=test_domain.com")
	a.Contains(s.AuthURL, "prompt=none")
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

func Test_Implements_LogoutProvider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, _ := NewCustomisedURL(
		"client_id",
		"client_secret",
		"http://localhost/callback",
		"https://example.com/auth",
		"https://example.com/token",
		"https://example.com",
		"https://example.com/userinfo",
		"https://example.com/logout",
	)
	a.Implements((*goth.LogoutProvider)(nil), provider)
}

func Test_EndSessionURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider, _ := NewCustomisedURL(
		"client_id",
		"client_secret",
		"http://localhost/callback",
		"https://example.com/auth",
		"https://example.com/token",
		"https://example.com",
		"https://example.com/userinfo",
		"https://example.com/logout",
	)

	// With all parameters
	logoutURL, err := provider.EndSessionURL("id_token_value", "http://localhost/post-logout", "some_state")
	a.NoError(err)
	a.Contains(logoutURL, "https://example.com/logout")
	a.Contains(logoutURL, "id_token_hint=id_token_value")
	a.Contains(logoutURL, "post_logout_redirect_uri="+url.QueryEscape("http://localhost/post-logout"))
	a.Contains(logoutURL, "state=some_state")
	a.NotContains(logoutURL, "client_id=")

	// Without id_token_hint, should include client_id
	logoutURL, err = provider.EndSessionURL("", "http://localhost/post-logout", "")
	a.NoError(err)
	a.Contains(logoutURL, "client_id=client_id")
	a.NotContains(logoutURL, "id_token_hint=")
	a.NotContains(logoutURL, "state=")

	// With only id_token_hint
	logoutURL, err = provider.EndSessionURL("id_token_value", "", "")
	a.NoError(err)
	a.Contains(logoutURL, "id_token_hint=id_token_value")
	a.NotContains(logoutURL, "post_logout_redirect_uri=")
}

func Test_EndSessionURL_NoEndpoint(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Provider without end_session_endpoint
	provider := openidConnectProvider()
	_, err := provider.EndSessionURL("id_token", "http://localhost", "state")
	a.Error(err)
	a.Contains(err.Error(), "does not support RP-Initiated Logout")
}

func openidConnectProvider() *Provider {
	provider, _ := New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost/foo", server.URL)
	return provider
}
