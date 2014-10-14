package twitter

import (
	"encoding/json"
	"errors"

	"github.com/markbates/goth"
	"github.com/mrjones/oauth"
)

// Session stores data during the auth process with Twitter.
type Session struct {
	AuthURL      string
	AccessToken  *oauth.AccessToken
	RequestToken *oauth.RequestToken
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Twitter provider.
func (self Session) GetAuthURL() (string, error) {
	if self.AuthURL == "" {
		return "", errors.New("an AuthURL has not be set")
	}
	return self.AuthURL, nil
}

// Authorize the session with Twitter and return the access token to be stored for future use.
func (self *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	accessToken, err := p.consumer.AuthorizeToken(self.RequestToken, params.Get("oauth_verifier"))
	if err != nil {
		return "", err
	}
	self.AccessToken = accessToken
	return accessToken.Token, err
}

// Marshal the session into a string
func (self Session) Marshal() string {
	b, _ := json.Marshal(self)
	return string(b)
}

func (self Session) String() string {
	return self.Marshal()
}
