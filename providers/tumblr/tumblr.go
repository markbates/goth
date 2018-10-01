// Package tumblr implements the OAuth protocol for authenticating users through Tumblr.
// This package can be used as a reference implementation of an OAuth provider for Goth.
package tumblr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/markbates/goth"
	"github.com/mrjones/oauth"
	"golang.org/x/oauth2"
)

var (
	requestURL      = "https://www.tumblr.com/oauth/request_token"
	authorizeURL    = "https://www.tumblr.com/oauth/authorize"
	tokenURL        = "https://www.tumblr.com/oauth/access_token"
	endpointProfile = "https://api.tumblr.com/v2/user/info"
)

// user/update_token

// New creates a new Tumblr provider, and sets up important connection details.
// You should always call `tumblr.New` to get a new Provider. Never try to create
// one manually.
//
// If you'd like to use authenticate instead of authorize, use NewAuthenticate instead.
func New(clientKey, secret, callbackURL string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "tumblr",
	}
	p.consumer = newConsumer(p, authorizeURL)
	return p
}

// NewAuthenticate is the almost same as New.
// NewAuthenticate uses the authenticate URL instead of the authorize URL.
func NewAuthenticate(clientKey, secret, callbackURL string) *Provider {
	return New(clientKey, secret, callbackURL)
}

// Provider is the implementation of `goth.Provider` for accessing Tumblr.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	debug        bool
	consumer     *oauth.Consumer
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

// Debug sets the logging of the OAuth client to verbose.
func (p *Provider) Debug(debug bool) {
	p.debug = debug
}

// BeginAuth asks Tumblr for an authentication end-point and a request token for a session.
// Tumblr does not support the "state" variable.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	requestToken, url, err := p.consumer.GetRequestTokenAndUrl(p.CallbackURL)
	session := &Session{
		AuthURL:      url,
		RequestToken: requestToken,
	}
	return session, err
}

// FetchUser will go to Tumblr and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		Provider: p.Name(),
	}

	if sess.AccessToken == nil {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	response, err := p.consumer.Get(endpointProfile, map[string]string{}, sess.AccessToken)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	if err = json.NewDecoder(response.Body).Decode(&user.RawData); err != nil {
		return user, err
	}

	res, ok := user.RawData["response"].(map[string]interface{})
	if !ok {
		return user, errors.New("could not decode response")
	}
	resUser, ok := res["user"].(map[string]interface{})
	if !ok {
		return user, errors.New("could not decode user")
	}

	user.Name = resUser["name"].(string)
	user.NickName = resUser["name"].(string)
	user.AccessToken = sess.AccessToken.Token
	user.AccessTokenSecret = sess.AccessToken.Secret
	return user, err
}

func newConsumer(provider *Provider, authURL string) *oauth.Consumer {
	c := oauth.NewConsumer(
		provider.ClientKey,
		provider.Secret,
		oauth.ServiceProvider{
			RequestTokenUrl:   requestURL,
			AuthorizeTokenUrl: authURL,
			AccessTokenUrl:    tokenURL,
		})

	c.Debug(provider.debug)
	return c
}

// RefreshToken refresh token is not provided by Tumblr
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by Tumblr")
}

// RefreshTokenAvailable refresh token is not provided by Tumblr
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
