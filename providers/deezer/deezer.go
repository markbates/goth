// Package deezer implements the OAuth2 protocol for authenticating users through Deezer.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package deezer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://connect.deezer.com/oauth/auth.php"
	tokenURL        string = "https://connect.deezer.com/oauth/access_token.php"
	endpointProfile string = "https://api.deezer.com/user/me"
)

// Provider is the implementation of `goth.Provider` for accessing Deezer.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// New creates a new Deezer provider and sets up important connection details.
// You should always call `deezer.New` to get a new provider. Never try to
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
	return "deezer"
}

// Debug is a no-op for the deezer package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Deezer for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser goes to Deezer to access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
		ExpiresAt:   sess.ExpiresAt,
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
	return user, err
}

// [Private] userFromReader will decode the json user and set the
// *goth.User attributes
func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"firstname"`
		LastName  string `json:"lastname"`
		NickName  string `json:"name"`
		AvatarURL string `json:"picture"`
		Location  string `json:"city"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.UserID = u.ID
	user.Email = u.Email
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.NickName = u.NickName
	user.AvatarURL = u.AvatarURL
	user.Location = u.Location

	return nil
}

// [Private] newConfig creates a new OAuth2 config
func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{
			"email",
		},
	}

	defaultScopes := map[string]struct{}{
		"email": {},
	}

	for _, scope := range scopes {
		if _, exists := defaultScopes[scope]; !exists {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}

//RefreshTokenAvailable refresh token is not provided by deezer
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

//RefreshToken refresh token is not provided by deezer
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by deezer")
}
