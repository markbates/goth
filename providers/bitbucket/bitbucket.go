// Package bitbucket implements the OAuth2 protocol for authenticating users through Bitbucket.
package bitbucket

import (
	"bytes"
	"encoding/json"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

const (
	authURL         string = "https://bitbucket.org/site/oauth2/authorize"
	tokenURL        string = "https://bitbucket.org/site/oauth2/access_token"
	endpointProfile string = "https://api.bitbucket.org/2.0/user"
	endpointEmail   string = "https://api.bitbucket.org/2.0/user/emails"
)

// New creates a new Bitbucket provider, and sets up important connection details.
// You should always call `bitbucket.New` to get a new Provider. Never try to create
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

// Provider is the implementation of `goth.Provider` for accessing Bitbucket.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "bitbucket"
}

// Debug is a no-op for the bitbucket package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Bitbucket for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Bitbucket and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	response, err := http.Get(endpointProfile + "?access_token=" + url.QueryEscape(sess.AccessToken))
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

	response, err = http.Get(endpointEmail + "?access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}
	defer response.Body.Close()

	bits, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = emailFromReader(bytes.NewReader(bits), &user)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID    string `json:"uuid"`
		Links struct {
			Avatar struct {
				URL string `json:"href"`
			} `json:"avatar"`
		} `json:"links"`
		Email    string `json:"email"`
		Username string `json:"username"`
		Name     string `json:"display_name"`
		Location string `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.NickName = u.Username
	user.AvatarURL = u.Links.Avatar.URL
	user.UserID = u.ID
	user.Location = u.Location

	return err
}

func emailFromReader(reader io.Reader, user *goth.User) error {
	e := struct {
		Values []struct {
			Email string `json:"email"`
		} `json:"values"`
	}{}

	err := json.NewDecoder(reader).Decode(&e)
	if err != nil {
		return err
	}

	if len(e.Values) > 0 {
		user.Email = e.Values[0].Email
	}

	return err
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

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
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
