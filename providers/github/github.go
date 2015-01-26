// Package github implements the OAuth2 protocol for authenticating users through Github.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"code.google.com/p/goauth2/oauth"
	"github.com/markbates/goth"
)

const (
	authURL         string = "https://github.com/login/oauth/authorize"
	tokenURL        string = "https://github.com/login/oauth/access_token"
	endpointProfile string = "https://api.github.com/user"
)

// New creates a new Github provider, and sets up important connection details.
// You should always call `github.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
		Scopes:      []string{},
	}
	p.config = newConfig(p)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Github.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	Scopes      []string
	config      *oauth.Config
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "github"
}

// Debug is a no-op for the github package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Github for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.addScopeParam(p.config.AuthCodeURL(state))
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Github and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
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
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

// Allow user to set a list of scopes to request from Github
// * https://developer.github.com/v3/oauth/#scopes
func (p *Provider) SetScopes(scopes []string) {
	if len(scopes) > 0 {
		for _, scope := range scopes {
			p.Scopes = append(p.Scopes, scope)
		}
	} else {
		p.Scopes = []string{}
	}
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID       int    `json:"id"`
		Email    string `json:"email"`
		Bio      string `json:"bio"`
		Name     string `json:"name"`
		Picture  string `json:"avatar_url"`
		Location string `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.NickName = u.Name
	user.Email = u.Email
	user.Description = u.Bio
	user.AvatarURL = u.Picture
	user.UserID = strconv.Itoa(u.ID)
	user.Location = u.Location

	return err
}

func newConfig(provider *Provider) *oauth.Config {
	c := &oauth.Config{
		ClientId:     provider.ClientKey,
		ClientSecret: provider.Secret,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		RedirectURL:  provider.CallbackURL,
	}
	return c
}

func (p *Provider) addScopeParam(url string) string {
	if len(p.Scopes) > 0 {
		return fmt.Sprintf("%s&scope=%s", url, strings.Join(p.Scopes, ","))
	} else {
		return url
	}
}
