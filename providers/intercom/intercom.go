// Package intercom implements the OAuth protocol for authenticating users through Intercom.
package intercom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	authURL  string = "https://app.intercom.io/oauth"
	tokenURL string = "https://api.intercom.io/auth/eagle/token?client_secret=%s"
	userURL  string = "https://api.intercom.io/me"
)

// New creates the new Intercom provider
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Intercom
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "intercom"
}

// Debug is a no-op for the intercom package
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Intercom for an authentication end-point
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will fetch basic information about Intercom admin
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
		ExpiresAt:   sess.ExpiresAt,
	}

	request, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return user, err
	}
	request.Header.Add("Accept", "application/json")
	request.SetBasicAuth(sess.AccessToken, "")

	response, err := http.DefaultClient.Do(request)

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
		ID     string `json:"id"`
		Email  string `json:"email"`
		Name   string `json:"name"`
		Link   string `json:"link"`
		Avatar struct {
			URL string `json:"image_url"`
		} `json:"avatar"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.FirstName, user.LastName = splitName(u.Name)
	user.Email = u.Email
	user.AvatarURL = u.Avatar.URL
	user.UserID = u.ID

	return err
}

func splitName(name string) (string, string) {
	nameSplit := strings.SplitN(name, " ", 2)
	firstName := nameSplit[0]

	var lastName string
	if len(nameSplit) == 2 {
		lastName = nameSplit[1]
	}

	return firstName, lastName
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: fmt.Sprintf(tokenURL, provider.Secret),
		},
	}

	return c
}

// RefreshToken refresh token is not provided by Intercom
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by Intercom")
}

// RefreshTokenAvailable refresh token is not provided by Intercom
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
