// Package facebook implements the OAuth2 protocol for authenticating users through Facebook.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package facebook

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
	authURL         string = "https://www.facebook.com/dialog/oauth"
	tokenURL        string = "https://graph.facebook.com/oauth/access_token"
	endpointProfile string = "https://graph.facebook.com/me?fields=email,first_name,last_name,link,bio,id,name,picture,location"
)

// New creates a new Facebook provider, and sets up important connection details.
// You should always call `facebook.New` to get a new Provider. Never try to create
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

// Provider is the implementation of `goth.Provider` for accessing Facebook.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth.Config
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "facebook"
}

// Debug is a no-op for the facebook package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Facebook for an authentication end-point.
func (p *Provider) BeginAuth() (goth.Session, error) {
	url := p.config.AuthCodeURL("state")
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Facebook and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{AccessToken: sess.AccessToken}

	response, err := http.Get(endpointProfile + "&access_token=" + url.QueryEscape(sess.AccessToken))
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

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Bio     string `json:"bio"`
		Name    string `json:"name"`
		Link    string `json:"link"`
		Picture struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
		Location struct {
			Name string `json:"name"`
		} `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.NickName = u.Name
	user.Email = u.Email
	user.Description = u.Bio
	user.AvatarURL = u.Picture.Data.URL
	user.UserID = u.ID
	user.Location = u.Location.Name

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
