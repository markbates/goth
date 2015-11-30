package twitch

import (
	"encoding/json"
	"errors"

	"github.com/smagic39/goth"
	"golang.org/x/oauth2"
)

// Session stores data during the auth process with Twitch
type Session struct {
	AuthURL     string
	AccessToken string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on
// the Twitch provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("Twitch: An AuthURL has not been set")
	}
	return s.AuthURL, nil
}

// Authorize completes the authorization with Twitch and returns the access
// token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(oauth2.NoContext, params.Get("code"))
	if err != nil {
		return "", err
	}

	s.AccessToken = token.AccessToken
	return token.AccessToken, err
}

// Marshal marshals a session into a JSON string.
func (s Session) Marshal() string {
	j, _ := json.Marshal(s)
	return string(j)
}

// String is equivalent to Marshal. It returns a JSON representation of the
// of the session.
func (s Session) String() string {
	return s.Marshal()
}
