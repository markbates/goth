package lastfm

import (
	"encoding/json"
	"errors"

	"github.com/markbates/goth"
	"golang.org/x/net/context"
)

// Session stores data during the auth process with Lastfm.
type Session struct {
	AuthURL     string
	AccessToken string
	Login       string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the LastFM provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("an AuthURL has not be set")
	}
	return s.AuthURL, nil
}

// Authorize the session with LastFM and return the access token to be stored for future use.
func (s *Session) Authorize(ctx context.Context, provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	sess, err := p.GetSession(params.Get("token"))
	if err != nil {
		return "", err
	}
	s.AccessToken = sess["token"]
	s.Login = sess["login"]
	return sess["token"], err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}
