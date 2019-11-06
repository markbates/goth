// Package intuit_sandbox implements the OAuth2 protocol for authenticating users through intuit.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package intuitSandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/overlay-labs/goth"
	"golang.org/x/oauth2"
)

// These vars define the Authentication, Token, and API URLS for intuit_sandbox.
const (
	AuthURL    string = "https://appcenter.intuit.com/connect/oauth2"
	TokenURL   string = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
	ProfileURL string = "https://sandbox-accounts.platform.intuit.com/v1/openid_connect/userinfo"
)

// New creates a new intuit_sandbox provider, and sets up important connection details.
// You should always call `intuit_sandbox.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "intuit_sandbox",
	}
	p.config = newConfig(p, AuthURL, TokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing intuit_sandbox.
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

// Debug is a no-op for the github package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks intuit_sandbox for an authentication end-point.
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

// FetchUser will go to intuit_sandbox and access basic information about the user.
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

	aquery := []byte(`{ "query": "query { name { id defaultEmail firstName lastName } }" }`)
	query := waveQuery{}
	json.Unmarshal([]byte(aquery), &query)
	fmt.Println(query)

	req, err := http.NewRequest("POST", p.profileURL, bytes.NewBuffer(aquery))
	if err != nil {
		return user, err
	}
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

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		ID        string `json:"id"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Email     string `json:"defaultEmail"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.UserID = u.ID // The user's unique intuit_sandbox ID.
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.Email = u.Email
	return nil
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

//RefreshToken refresh token is not provided by intuit_sandbox
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by intuit_sandbox")
}

//RefreshTokenAvailable refresh token is not provided by intuit_sandbox
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
