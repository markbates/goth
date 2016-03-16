// Package uber implements the OAuth2 protocol for authenticating users through uber.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package uber

import (
	"encoding/json"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"net/http"
)

const (
	authURL         string = "https://login.uber.com/oauth/authorize"
	tokenURL        string = "https://login.uber.com/oauth/token"
	endpointProfile string = "https://api.uber.com/v1/me"
)

// Provider is the implementation of `goth.Provider` for accessing Uber.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// New creates a new Uber provider and sets up important connection details.
// You should always call `uber.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "uber"
}

// Debug is a no-op for the uber package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Uber for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Uber and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
	}
	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}
	defer resp.Body.Close()

	err = userFromReader(resp.Body, &user)
	return user, err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	} else {
		c.Scopes = append(c.Scopes, "profile")
	}

	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name      string `json:"first_name"`
		Email     string `json:"email"`
		ID        string `json:"uuid"`
		AvatarURL string `json:"picture"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = u.Email
	user.Name = u.Name
	user.UserID = u.ID
	user.AvatarURL = u.AvatarURL
	return nil
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(oauth2.NoContext, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
