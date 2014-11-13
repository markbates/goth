package gplus

import (
	"encoding/json"
	"errors"

	"code.google.com/p/goauth2/oauth"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with Facebook.
type Session struct {
	AuthURL     string
	AccessToken string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Google+ provider.
func (self Session) GetAuthURL() (string, error) {
	if self.AuthURL == "" {
		return "", errors.New("an AuthURL has not be set")
	}
	return self.AuthURL, nil
}

// Authorize the session with Google+ and return the access token to be stored for future use.
func (self *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	t := &oauth.Transport{Config: p.config}
	token, err := t.Exchange(params.Get("code"))
	if err != nil {
		return "", err
	}
	self.AccessToken = token.AccessToken
	return token.AccessToken, err
}

// Marshal the session into a string
func (self Session) Marshal() string {
	b, _ := json.Marshal(self)
	return string(b)
}

func (self Session) String() string {
	return self.Marshal()
}
