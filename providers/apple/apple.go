// Package `apple` implements the OAuth2 protocol for authenticating users through Apple.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package apple

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authEndpoint  = "https://appleid.apple.com/auth/authorize"
	tokenEndpoint = "https://appleid.apple.com/auth/token"
)

type Provider struct {
	providerName string
	clientId     string
	secret       string
	redirectURL  string
	config       *oauth2.Config
	httpClient   *http.Client
}

func New(clientId, secret, redirectURL string, httpClient *http.Client, scopes ...string) *Provider {
	p := &Provider{
		clientId:     clientId,
		secret:       secret,
		redirectURL:  redirectURL,
		providerName: "apple",
	}
	p.config = newConfig(p, scopes)
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

func (p Provider) Secret() string {
	return p.secret
}

func (p Provider) RedirectURL() string {
	return p.redirectURL
}

func (p Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

func (Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

func (Provider) FetchUser(goth.Session) (goth.User, error) {
	return goth.User{}, errors.New("not implemented")
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

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.clientId,
		ClientSecret: provider.secret,
		RedirectURL:  provider.redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authEndpoint,
			TokenURL: tokenEndpoint,
		},
		Scopes: make([]string, 0, len(scopes)),
	}

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
}
