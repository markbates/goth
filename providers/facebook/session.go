package facebook

import (
	"encoding/json"
	"errors"

	"github.com/markbates/goth"
	"golang.org/x/net/context"
)

// Session stores data during the auth process with Facebook.
type Session struct {
	AuthURL     string
	AccessToken string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Facebook provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("an AuthURL has not be set")
	}
	return s.AuthURL, nil
}

// Authorize the session with Facebook and return the access token to be stored for future use.
func (s *Session) Authorize(ctx context.Context, provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(ctx, params.Get("code"))
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
