// Package instagram implements the OAuth2 protocol for authenticating users through Instagram.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package instagram

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

var (
	authURL         = "https://api.instagram.com/oauth/authorize/"
	tokenURL        = "https://api.instagram.com/oauth/access_token"
	endPointProfile = "https://graph.instagram.com/me"
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
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	requestURL := endPointProfile + "?fields=id,username,account_type,media_count&access_token=" + url.QueryEscape(sess.AccessToken)

	response, err := p.Client().Get(requestURL)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	if err != nil {
		return user, err
	} else {
		return user, nil
	}
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID          string `json:"id"`
		UserName    string `json:"username"`
		AccountType string `json:"account_type"`
		MediaCount  int64  `json:"media_count"`
		Biography   string `json:"biography"`
		ProfileUrl  string `json:"profile_picture_url"`
		Name        string `json:"name"`

		// Add other fields as needed
	}{}
	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}
	user.UserID = u.ID
	user.NickName = u.UserName
	user.Description = u.Biography
	user.AvatarURL = u.ProfileUrl
	user.Name = u.Name
	// Set other fields as needed
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
			"instagram_business_basic",
		},
	}
	defaultScopes := map[string]struct{}{
		"instagram_business_basic": {},
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
