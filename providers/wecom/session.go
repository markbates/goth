package wecom

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with WeCom.
type Session struct {
	AuthURL     string
	AccessToken string
	UserID      string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the WeCom provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with WeCom and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.fetchToken()
	if err != nil {
		return "", err
	}
	s.AccessToken = token.AccessToken

	userID, err := p.fetchUserID(s, params.Get("code"))
	if err != nil {
		return "", err
	}
	s.UserID = userID

	return s.AccessToken, nil
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
