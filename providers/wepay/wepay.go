// Package wepay implements the OAuth2 protocol for authenticating users through wepay.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package wepay

import (
	"encoding/json"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const (
	authURL         string = "https://www.wepay.com/v2/oauth2/authorize"
	tokenURL        string = "https://wepayapi.com/v2/oauth2/token"
	endpointProfile string = "https://wepayapi.com/v2/user"
)

// Provider is the implementation of `goth.Provider` for accessing Wepay.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// New creates a new Wepay provider and sets up important connection details.
// You should always call `wepay.New` to get a new provider.  Never try to
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
	return "wepay"
}

// Debug is a no-op for the wepay package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Wepay for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Wepay and access basic information about the user.
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
	//Wepay is not recoginsing scope, if scope is not present as first paremeter
	newAuthURL := authURL

	if len(scopes) > 0 {
		newAuthURL = newAuthURL + "?scope=" + strings.Join(scopes, ",")
	} else {
		newAuthURL = newAuthURL + "?scope=view_user"
	}
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  newAuthURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Email    string `json:"email"`
		UserName string `json:"user_name"`
		ID       int    `json:"user_id"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = u.Email
	user.Name = u.UserName
	user.UserID = strconv.Itoa(u.ID)
	return nil
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {

	return nil, nil
}
