// Package intuitsandbox implements the OAuth2 protocol for authenticating users through Wave.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package intuitsandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/overlay-labs/goth"
	"golang.org/x/oauth2"
)

// These vars define the Authentication, Token, and API URLS for Wave.
const (
	AuthURL    string = "https://api.waveapps.com/oauth2/authorize"
	TokenURL   string = "https://api.waveapps.com/oauth2/token"
	ProfileURL string = "https://gql.waveapps.com/graphql/public"
)

// New creates a new Wave provider, and sets up important connection details.
// You should always call `wave.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "intuitsandbox",
	}
	p.config = newConfig(p, AuthURL, TokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Wave.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	profileURL   string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client is to do some stuff
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the intuitSandbox package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks intuitSandbox for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

type waveQuery struct {
	Query string
}

// FetchUser will go to intuit and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken: s.AccessToken,
		Provider:    p.Name(),
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	var jsonStr = []byte(`{"query":"query { user { id defaultEmail firstName lastName } }"}`)

	req, err := http.NewRequest("POST", ProfileURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		return user, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	var intuitUserMap map[string]map[string]map[string]interface{}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&waveUserMap)
	if err != nil {
		return user, err
	}

	user.RawData = intuitUserMap["data"]["user"]

	err = populateUserInfo(user.RawData, &user)
	return user, err
}

func populateUserInfo(userMap map[string]interface{}, user *goth.User) error {
	user.Email = stringValue(userMap["defaultEmail"])
	user.Name = stringValue(userMap["firstName"])
	user.LastName = stringValue(userMap["lastName"])
	user.UserID = stringValue(userMap["id"])
	return nil
}

func stringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	return v.(string)
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
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

//RefreshToken refresh token is not provided by wave
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by wave")
}

//RefreshTokenAvailable refresh token is not provided by wave
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
