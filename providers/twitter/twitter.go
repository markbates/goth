// Package twitter implements the OAuth protocol for authenticating users through Twitter.
// This package can be used as a reference implementation of an OAuth provider for Goth.
package twitter

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/markbates/goth"
	"github.com/mrjones/oauth"
)

const (
	requestURL      string = "https://api.twitter.com/oauth/request_token"
	authURL         string = "https://api.twitter.com/oauth/authorize"
	tokenURL        string = "https://api.twitter.com/oauth/access_token"
	endpointProfile string = "https://api.twitter.com/1.1/account/verify_credentials.json"
)

// New creates a new Twitter provider, and sets up important connection details.
// You should always call `twitter.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.consumer = newConsumer(p)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Twitter.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	debug       bool
	consumer    *oauth.Consumer
}

// Name is the name used to retrieve this provider later.
func (self *Provider) Name() string {
	return "twitter"
}

// Debug sets the logging of the OAuth client to verbose.
func (self *Provider) Debug(debug bool) {
	self.debug = debug
}

// BeginAuth asks Twitter for an authentication end-point and a request token for a session.
func (self *Provider) BeginAuth() (goth.Session, error) {
	requestToken, url, err := self.consumer.GetRequestTokenAndUrl(self.CallbackURL)
	session := &Session{
		AuthURL:      url,
		RequestToken: requestToken,
	}
	return session, err
}

// FetchUser will go to Twitter and access basic information about the user.
func (self *Provider) FetchUser(session goth.Session) (goth.User, error) {
	user := goth.User{}

	sess := session.(*Session)
	response, err := self.consumer.Get(
		endpointProfile,
		map[string]string{"include_entities": "false", "skip_status": "true"},
		sess.AccessToken)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	bits, err := ioutil.ReadAll(response.Body)
	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	user.Name = user.RawData["name"].(string)
	user.NickName = user.RawData["screen_name"].(string)
	user.Description = user.RawData["description"].(string)
	user.AvatarURL = user.RawData["profile_image_url"].(string)
	user.UserID = user.RawData["id_str"].(string)
	user.Location = user.RawData["location"].(string)
	user.AccessToken = sess.AccessToken.Token
	return user, err
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (self *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

func newConsumer(provider *Provider) *oauth.Consumer {
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
