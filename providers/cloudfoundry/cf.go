// Package cloudfoundry implements the OAuth2 protocol for authenticating users through Cloud Foundry
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package cloudfoundry

import (
	"bytes"
	"encoding/json"
	"github.com/markbates/goth"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// Provider is the implementation of `goth.Provider` for accessing Cloud Foundry.
type Provider struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	ClientKey   string
	Secret      string
	CallbackURL string
	Client      *http.Client
	config      *oauth2.Config
}

// New creates a new Cloud Foundry provider and sets up important connection details.
// You should always call `cloudfoundry.New` to get a new provider.  Never try to
// create one manually.
func New(uaaURL, clientKey, secret, callbackURL string, scopes ...string) *Provider {
	uaaURL = strings.TrimSuffix(uaaURL, "/")
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
		AuthURL:     uaaURL + "/oauth/authorize",
		TokenURL:    uaaURL + "/oauth/token",
		UserInfoURL: uaaURL + "/userinfo",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "cloudfoundry"
}

// Debug is a no-op for the cloudfoundry package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Cloud Foundry for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Cloud Foundry and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
	}
	req, err := http.NewRequest("GET", p.UserInfoURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := p.Client.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}
	defer resp.Body.Close()

	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.AuthURL,
			TokenURL: provider.TokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name  string `json:"user_name"`
		Email string `json:"email"`
		ID    string `json:"user_id"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Name = u.Name
	user.NickName = u.Name
	user.UserID = u.ID
	user.Email = u.Email
	return nil
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ctx := context.WithValue(oauth2.NoContext, oauth2.HTTPClient, p.Client)
	ts := p.config.TokenSource(ctx, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
