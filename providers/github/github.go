// Package github implements the OAuth2 protocol for authenticating users through Github.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

// These vars define the Authentication, Token, and API URLS for GitHub. If
// using GitHub enterprise you should change these values before calling New.
//
// Examples:
//	github.AuthURL = "https://github.acme.com/login/oauth/authorize
//	github.TokenURL = "https://github.acme.com/login/oauth/access_token
//	github.ProfileURL = "https://github.acme.com/api/v3/user
var (
	AuthURL    = "https://github.com/login/oauth/authorize"
	TokenURL   = "https://github.com/login/oauth/access_token"
	ProfileURL = "https://api.github.com/user"
)

// New creates a new Github provider, and sets up important connection details.
// You should always call `github.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Github.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "github"
}

// Debug is a no-op for the github package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Github for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Github and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}

	response, err := http.Get(ProfileURL + "?access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}
	defer response.Body.Close()

	bits, err := ioutil.ReadAll(response.Body)
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

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID       int    `json:"id"`
		Email    string `json:"email"`
		Bio      string `json:"bio"`
		Name     string `json:"name"`
		Login    string `json:"login"`
		Picture  string `json:"avatar_url"`
		Location string `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.NickName = u.Login
	user.Email = u.Email
	user.Description = u.Bio
	user.AvatarURL = u.Picture
	user.UserID = strconv.Itoa(u.ID)
	user.Location = u.Location

	return err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  AuthURL,
			TokenURL: TokenURL,
		},
		Scopes: []string{},
	}

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
}

//RefreshToken refresh token is not provided by github
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by github")
}

//RefreshTokenAvailable refresh token is not provided by github
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
