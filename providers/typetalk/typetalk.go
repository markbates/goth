// Package typetalk implements the OAuth2 protocol for authenticating users through Typetalk.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
//
// Typetalk API Docs: https://developer.nulab-inc.com/docs/typetalk/auth/
package typetalk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://typetalk.com/oauth2/authorize"
	tokenURL        string = "https://typetalk.com/oauth2/access_token"
	endpointProfile string = "https://typetalk.com/api/v1/profile"
	endpointUser    string = "https://typetalk.com/api/v1/accounts/profile/"
)

// Provider is the implementation of `goth.Provider` for accessing Typetalk.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new Typetalk provider and sets up important connection details.
// You should always call `typetalk.New` to get a new provider. Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "typetalk",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers os 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns HTTP client.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the typetalk package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Typetalk for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Typetalk and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	// Get username
	response, err := p.Client().Get(endpointProfile + "?access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user name", p.providerName, response.StatusCode)
	}

	bits, err := io.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	u := struct {
		Account struct {
			Name string `json:"name"`
		} `json:"account"`
	}{}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&u)
	if err != nil {
		return user, err
	}

	// Get user profile info
	response, err = p.Client().Get(endpointUser + u.Account.Name + "?access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch profile", p.providerName, response.StatusCode)
	}

	bits, err = io.ReadAll(response.Body)
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
		c.Scopes = append(c.Scopes, "my")
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Account struct {
			ID             int64  `json:"id"`
			Name           string `json:"name"`
			FullName       string `json:"fullName"`
			Suggestion     string `json:"suggestion"`
			MailAddress    string `json:"mailAddress"`
			ImageURL       string `json:"imageUrl"`
			CreatedAt      string `json:"createdAt"`
			UpdatedAt      string `json:"updatedAt"`
			ImageUpdatedAt string `json:"imageUpdatedAt"`
		} `json:"account"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.UserID = strconv.FormatInt(u.Account.ID, 10)
	user.Email = u.Account.MailAddress
	user.Name = u.Account.FullName
	user.NickName = u.Account.Name
	user.AvatarURL = u.Account.ImageURL
	return nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}
