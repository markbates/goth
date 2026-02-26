// Package yammer implements the OAuth2 protocol for authenticating users through yammer.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package yammer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://www.yammer.com/oauth2/authorize"
	tokenURL        string = "https://www.yammer.com/oauth2/access_token"
	endpointProfile string = "https://www.yammer.com/api/v1/users/current.json"
)

// Provider is the implementation of `goth.Provider` for accessing Yammer.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new Yammer provider and sets up important connection details.
// You should always call `yammer.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "yammer",
	}
	p.config = newConfig(p, scopes)
	return p
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

// Debug is a no-op for the yammer package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Yammer for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Yammer and access basic information about the user.
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

	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}

	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)

	response, err := p.Client().Do(req)
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

	err = populateUser(user.RawData, &user)
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

func populateUser(userMap map[string]interface{}, user *goth.User) error {
	user.Email = stringValue(userMap["email"])
	user.Name = stringValue(userMap["full_name"])
	user.NickName = stringValue(userMap["full_name"])
	user.UserID = strconv.FormatFloat(userMap["id"].(float64), 'f', -1, 64)
	user.Location = stringValue(userMap["location"])
	return nil
}

func stringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	return v.(string)
}

// RefreshToken refresh token is not provided by yammer
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by yammer")
}

// RefreshTokenAvailable refresh token is not provided by yammer
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
