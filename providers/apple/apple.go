// Package `apple` implements the OAuth2 protocol for authenticating users through Apple.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package apple

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authEndpoint  = "https://appleid.apple.com/auth/authorize"
	tokenEndpoint = "https://appleid.apple.com/auth/token"

	ScopeEmail = "email"
	ScopeName  = "name"

	AppleAudOrIss = "https://appleid.apple.com"
)

type Provider struct {
	providerName         string
	clientId             string
	secret               string
	redirectURL          string
	config               *oauth2.Config
	httpClient           *http.Client
	formPostResponseMode bool
	timeNowFn            func() time.Time
}

func New(clientId, secret, redirectURL string, httpClient *http.Client, scopes ...string) *Provider {
	p := &Provider{
		clientId:     clientId,
		secret:       secret,
		redirectURL:  redirectURL,
		providerName: "apple",
	}
	p.configure(scopes)
	p.httpClient = httpClient
	return p
}

func (p Provider) Name() string {
	return p.providerName
}

func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p Provider) ClientId() string {
	return p.clientId
}

type SecretParams struct {
	pkcs8PrivateKey, teamId, keyId, clientId string
	iat, exp                                 int
}

func MakeSecret(sp SecretParams) (*string, error) {
	block, rest := pem.Decode([]byte(strings.TrimSpace(sp.pkcs8PrivateKey)))
	if block == nil || len(rest) > 0 {
		return nil, errors.New("invalid private key")
	}
	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": sp.teamId,
		"iat": sp.iat,
		"exp": sp.exp,
		"aud": AppleAudOrIss,
		"sub": sp.clientId,
	})
	token.Header["kid"] = sp.keyId
	ss, err := token.SignedString(pk)
	return &ss, err
}

func (p Provider) Secret() string {
	return p.secret
}

func (p Provider) RedirectURL() string {
	return p.redirectURL
}

func (p Provider) BeginAuth(state string) (goth.Session, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 1)
	if p.formPostResponseMode {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}
	return &Session{
		AuthURL: p.config.AuthCodeURL(state, opts...),
	}, nil
}

func (Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

// Apple doesn't seem to provide a user profile endpoint like all the other providers do.
// Therefore this will return a User with only the  the unique identifier obtained through authorization.
// A full name and email can be obtained from the form post response
// to the redirect page following authentication.
func (p Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	if s.AccessToken == "" {
		return goth.User{}, fmt.Errorf("no access token obtained for session with provider %s", p.Name())
	}
	return goth.User{
		Provider:          p.Name(),
		UserID:            s.ID.Sub,
		AccessToken:       s.AccessToken,
		RefreshToken:      s.RefreshToken,
		ExpiresAt:         s.ExpiresAt,
	}, nil
}

// Debug is a no-op for the apple package.
func (Provider) Debug(bool) {}

func (p Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.httpClient)
}

func (p Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

func (Provider) RefreshTokenAvailable() bool {
	return true
}

func (p *Provider) configure(scopes []string) {
	c := &oauth2.Config{
		ClientID:     p.clientId,
		ClientSecret: p.secret,
		RedirectURL:  p.redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authEndpoint,
			TokenURL: tokenEndpoint,
		},
		Scopes: make([]string, 0, len(scopes)),
	}

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
		if scope == "name" || scope == "email" {
			p.formPostResponseMode = true
		}
	}

	p.config = c
}
