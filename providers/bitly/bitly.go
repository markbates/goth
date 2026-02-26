// Package bitly implements the OAuth2 protocol for authenticating users through Bitly.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package bitly

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authEndpoint    string = "https://bitly.com/oauth/authorize"
	tokenEndpoint   string = "https://api-ssl.bitly.com/oauth/access_token"
	profileEndpoint string = "https://api-ssl.bitly.com/v4/user"
)

// New creates a new Bitly provider and sets up important connection details.
// You should always call `bitly.New` to get a new provider. Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.newConfig(scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Bitly.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Ensure `bitly.Provider` implements `goth.Provider`.
var _ goth.Provider = &Provider{}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type).
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the bitly package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Bitly for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Bitly and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	u := goth.User{
		Provider:    p.Name(),
		AccessToken: s.AccessToken,
	}

	if u.AccessToken == "" {
		return u, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", profileEndpoint, nil)
	if err != nil {
		return u, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", u.AccessToken))

	resp, err := p.Client().Do(req)
	if err != nil {
		return u, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return u, err
	}

	if err := json.NewDecoder(bytes.NewReader(buf)).Decode(&u.RawData); err != nil {
		return u, err
	}

	return u, userFromReader(bytes.NewReader(buf), &u)
}

// RefreshToken refresh token is not provided by bitly.
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by bitly")
}

// RefreshTokenAvailable refresh token is not provided by bitly.
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

func (p *Provider) newConfig(scopes []string) {
	conf := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RedirectURL:  p.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authEndpoint,
			TokenURL: tokenEndpoint,
		},
		Scopes: make([]string, 0),
	}

	conf.Scopes = append(conf.Scopes, scopes...)

	p.config = conf
}

func userFromReader(reader io.Reader, user *goth.User) (err error) {
	u := struct {
		Login  string `json:"login"`
		Name   string `json:"name"`
		Emails []struct {
			Email      string `json:"email"`
			IsPrimary  bool   `json:"is_primary"`
			IsVerified bool   `json:"is_verified"`
		} `json:"emails"`
	}{}
	if err := json.NewDecoder(reader).Decode(&u); err != nil {
		return err
	}

	user.Name = u.Name
	user.NickName = u.Login
	user.Email, err = getEmail(u.Emails)
	return err
}

func getEmail(emails []struct {
	Email      string `json:"email"`
	IsPrimary  bool   `json:"is_primary"`
	IsVerified bool   `json:"is_verified"`
}) (string, error) {
	for _, email := range emails {
		if email.IsPrimary && email.IsVerified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("The user does not have a verified, primary email address on Bitly")
}
