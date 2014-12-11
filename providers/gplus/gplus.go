// Package gplus implements the OAuth2 protocol for authenticating users through Google+.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package gplus

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"code.google.com/p/goauth2/oauth"
	"github.com/markbates/goth"
)

const (
	authURL         string = "https://accounts.google.com/o/oauth2/auth"
	tokenURL        string = "https://accounts.google.com/o/oauth2/token"
	scope           string = "profile email openid"
	endpointProfile string = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// New creates a new Google+ provider, and sets up important connection details.
// You should always call `gplus.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.config = newConfig(p)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Google+.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth.Config
}

// Name is the name used to retrieve this provider later.
func (self *Provider) Name() string {
	return "gplus"
}

// Debug is a no-op for the gplus package.
func (self *Provider) Debug(debug bool) {}

// BeginAuth asks Google+ for an authentication end-point.
func (self *Provider) BeginAuth() (goth.Session, error) {
	url := self.config.AuthCodeURL("state")
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Google+ and access basic information about the user.
func (self *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{AccessToken: sess.AccessToken}
	response, err := http.Get(endpointProfile + "?access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
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

// UnmarshalSession will unmarshal a JSON string into a session.
func (self *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Link    string `json:"link"`
		Picture string `json:"picture"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.NickName = u.Name
	user.Email = u.Email
	//user.Description = u.Bio
	user.AvatarURL = u.Picture
	user.UserID = u.ID
	//user.Location = u.Location.Name

	return err
}

func newConfig(provider *Provider) *oauth.Config {
	c := &oauth.Config{
		ClientId:     provider.ClientKey,
		ClientSecret: provider.Secret,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		RedirectURL:  provider.CallbackURL,
		Scope:        scope,
	}
	return c
}
