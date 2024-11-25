// Package instagram implements the OAuth2 protocol for authenticating users through Instagram.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package instagram

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

var (
	authURL         = "https://api.instagram.com/oauth/authorize/"
	tokenURL        = "https://api.instagram.com/oauth/access_token"
	endPointProfile = "https://api.instagram.com/v1/users/self/"
)

// New creates a new Instagram provider, and sets up important connection details.
// You should always call `instagram.New` to get a new Provider. Never try to craete
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "instagram",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Instagram
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	UserAgent    string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug TODO
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Instagram for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Instagram and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	response, err := p.Client().Get(endPointProfile + "?access_token=" + url.QueryEscape(sess.AccessToken))

	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := io.ReadAll(response.Body)
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
		Data struct {
			ID             string `json:"id"`
			UserName       string `json:"username"`
			FullName       string `json:"full_name"`
			ProfilePicture string `json:"profile_picture"`
			Bio            string `json:"bio"`
			Website        string `json:"website"`
			Counts         struct {
				Media      int `json:"media"`
				Follows    int `json:"follows"`
				FollowedBy int `json:"followed_by"`
			} `json:"counts"`
		} `json:"data"`
	}{}
	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}
	user.UserID = u.Data.ID
	user.Name = u.Data.FullName
	user.NickName = u.Data.UserName
	user.AvatarURL = u.Data.ProfilePicture
	user.Description = u.Data.Bio
	return err
}

func newConfig(p *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RedirectURL:  p.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{
			"basic",
		},
	}
	defaultScopes := map[string]struct{}{
		"basic": {},
	}

	for _, scope := range scopes {
		if _, exists := defaultScopes[scope]; !exists {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}

// RefreshToken refresh token is not provided by instagram
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by instagram")
}

// RefreshTokenAvailable refresh token is not provided by instagram
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
