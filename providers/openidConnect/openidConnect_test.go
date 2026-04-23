package openidConnect

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

	// The mock server advertises ["plain","S256"] so PKCE must be used with S256.
	a.Equal("S256", provider.PKCEMethod)
	a.NotEmpty(s.CodeVerifier)
	a.Contains(s.AuthURL, "code_challenge=")
	a.Contains(s.AuthURL, "code_challenge_method=S256")
}

func Test_BeginAuth_PKCE_S256_Challenge(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := openidConnectProvider()
	session, err := provider.BeginAuth("test_state")
	a.NoError(err)
	s := session.(*Session)

	// Verify that the code_challenge in the URL matches the S256 of the stored verifier.
	expected := generateS256Challenge(s.CodeVerifier)
	a.Contains(s.AuthURL, "code_challenge="+expected)
}

func Test_BeginAuth_NoPKCE_WhenNotAdvertised(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Spin up a server that does NOT advertise code_challenge_methods_supported.
	noPKCEServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","token_endpoint":"https://www.googleapis.com/oauth2/v4/token","userinfo_endpoint":"https://www.googleapis.com/oauth2/v3/userinfo"}`)
	}))
	defer noPKCEServer.Close()

	provider, err := New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost/foo", noPKCEServer.URL)
	a.NoError(err)
	a.Equal("", provider.PKCEMethod)

	session, err := provider.BeginAuth("test_state")
	a.NoError(err)
	s := session.(*Session)
	a.Empty(s.CodeVerifier)
	a.NotContains(s.AuthURL, "code_challenge")
	a.NotContains(s.AuthURL, "code_challenge_method")
}

func Test_SelectPKCEMethod(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Equal("S256", selectPKCEMethod([]string{"plain", "S256"}))
	a.Equal("S256", selectPKCEMethod([]string{"S256"}))
	a.Equal("plain", selectPKCEMethod([]string{"plain"}))
	a.Equal("", selectPKCEMethod([]string{}))
	a.Equal("", selectPKCEMethod(nil))
	a.Equal("", selectPKCEMethod([]string{"other"}))
}

func Test_GenerateCodeVerifier(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	v, err := generateCodeVerifier()
	a.NoError(err)
	// 32 bytes base64url-encoded without padding = 43 chars
	a.Equal(43, len(v))
	// All chars must be URL-safe base64 alphabet
	for _, c := range v {
		a.Contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", string(c))
	}

	// Two verifiers must differ (with overwhelming probability)
	v2, _ := generateCodeVerifier()
	a.NotEqual(v, v2)
}

func Test_GenerateS256Challenge(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Known test vector from RFC 7636 Appendix B:
	// code_verifier = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
	// code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
	a.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", generateS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
}

func Test_New_PKCE_MethodSelectedFromDiscovery(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Mock server advertises only "plain"
	plainOnlyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","token_endpoint":"https://www.googleapis.com/oauth2/v4/token","userinfo_endpoint":"https://www.googleapis.com/oauth2/v3/userinfo","code_challenge_methods_supported":["plain"]}`)
	}))
	defer plainOnlyServer.Close()

	provider, err := New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost/foo", plainOnlyServer.URL)
	a.NoError(err)
	a.Equal("plain", provider.PKCEMethod)
}

func Test_BeginAuth_PKCE_PlainMethod(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	// Mock server advertises only "plain"
	plainOnlyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth","token_endpoint":"https://www.googleapis.com/oauth2/v4/token","userinfo_endpoint":"https://www.googleapis.com/oauth2/v3/userinfo","code_challenge_methods_supported":["plain"]}`)
	}))
	defer plainOnlyServer.Close()

	provider, err := New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost/foo", plainOnlyServer.URL)
	a.NoError(err)

	session, err := provider.BeginAuth("test_state")
	a.NoError(err)
	s := session.(*Session)
	a.NotEmpty(s.CodeVerifier)
	// For "plain", challenge == verifier
	a.Contains(s.AuthURL, "code_challenge="+s.CodeVerifier)
	a.Contains(s.AuthURL, "code_challenge_method=plain")
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

func openidConnectProvider() *Provider {
	provider, _ := New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost/foo", server.URL)
	return provider
}
