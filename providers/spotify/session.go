package spotify

import (
	"encoding/json"
	"errors"

	"github.com/markbates/goth"
	"golang.org/x/net/context"
)

// Session stores data during the auth process with Spotify.
type Session struct {
	AuthURL     string
	AccessToken string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the
// Spotify provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("spotify: AuthURL has not been set")
	}
	return s.AuthURL, nil
}

// Authorize completes the the authorization with Spotify and returns the access
// token to be stored for future use.
func (s Session) Authorize(ctx context.Context, provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(ctx, params.Get("code"))
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

// String is equivalent to Marshal.  It returns a JSON representation of the session.
func (s Session) String() string {
	return s.Marshal()
}
