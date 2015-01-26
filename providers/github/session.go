package github

import (
	"encoding/json"
	"errors"

	"golang.org/x/oauth2"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with Github.
type Session struct {
	AuthURL     string
	AccessToken string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Github provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("an AuthURL has not be set")
	}
	return s.AuthURL, nil
}

// Authorize the session with Github and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(oauth2.NoContext, params.Get("code"))
	if err != nil {
		return "", err
	}

	s.AccessToken = token.AccessToken
	return token.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}
