// Package meetup implements the OAuth2 protocol for authenticating users through meetup.com .
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package meetup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://secure.meetup.com/oauth2/authorize"
	tokenURL        string = "https://secure.meetup.com/oauth2/access"
	endpointProfile string = "https://api.meetup.com/2/member/self"
)

// New creates a new Meetup provider, and sets up important connection details.
// You should always call `meetup.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "meetup",
	}
	// register this meetup.com provider as broken for oauth2 RetrieveToken
	oauth2.RegisterBrokenAuthHeaderProvider(tokenURL)
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing meetup.com .
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
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

// Debug is a no-op for the meetup package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks meetup.com for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to meetup.com and access basic information about the user.
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

	request, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}

	request.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	response, err := p.Client().Do(request)
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
	}

	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		ID      uint64 `json:"id"`
		Name    string `json:"name"`
		Picture string `json:"photo_url"`
		Country string `json:"country"`
		City    string `json:"city"`
		State   string `json:"state"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.UserID = strconv.FormatUint(u.ID, 10)
	user.Name = u.Name
	user.NickName = u.Name

	var location string
	if len(u.City) > 0 {
		location = u.City
	}
	if len(u.State) > 0 {
		if len(location) > 0 {
			location = location + ", " + u.State
		} else {
			location = u.State
		}
	}
	if len(u.Country) > 0 {
		if len(location) > 0 {
			location = location + ", " + u.Country
		} else {
			location = u.Country
		}
	}

	user.Location = location
	user.AvatarURL = u.Picture
	return nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
