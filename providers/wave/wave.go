// Package wave implements the OAuth2 protocol for authenticating users through Wave.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package wave

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// These vars define the Authentication, Token, and API URLS for GitHub. If
// using GitHub enterprise you should change these values before calling New.
//
// Examples:
// AuthURL = "https://api.waveapps.com/oauth2/authorize"
// TokenURL = "https://api.waveapps.com/oauth2/token"
// ProfileURL = "https://gql.waveapps.com/graphql/public"
const (
	AuthURL    string = "https://api.waveapps.com/oauth2/authorize"
	TokenURL   string = "https://api.waveapps.com/oauth2/token"
	ProfileURL string = "https://gql.waveapps.com/graphql/public"
)

// New creates a new Github provider, and sets up important connection details.
// You should always call `github.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomizedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, ProfileURL, scopes...)
}

// NewCustomizedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomizedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileURL, emailURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "wave",
		profileURL:   profileURL,
	}
	p.config = newConfig(p, AuthURL, TokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Github.
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

// BeginAuth asks Github for an authentication end-point.
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

// FetchUser will go to Wave and access basic information about the user.
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

	const aquery = `{ query: "query { name { id userinfo } }" }`
	const query = waveQuery{}
	json.Unmarshal([]byte(aquery, &query))
	fmt.Println(query)

	response, err := p.Client().Get(p.profileURL + "?access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("Wave API responded with a %d trying to fetch user information", response.StatusCode)
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
	}

	if user.Email == "" {
		for _, scope := range p.config.Scopes {
			if strings.TrimSpace(scope) == "user" || strings.TrimSpace(scope) == "user:email" {
				user.Email, err = getPrivateMail(p, sess)
				if err != nil {
					return user, err
				}
				break
			}
		}
	}
	return user, err
}
