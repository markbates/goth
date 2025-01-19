package direct

import (
	"encoding/json"
	"errors"

	"github.com/markbates/goth"
)

type Session struct {
	AuthURL string
	Email   string
}

func (s *Session) GetAuthURL() (string, error) {
	return s.AuthURL, nil
}

func (s *Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	email := params.Get("email")
	password := params.Get("password")

	directProvider, ok := provider.(*Provider)
	if !ok {
		return "", errors.New("invalid provider type")
	}

	session, err := directProvider.IssueSession(email, password)
	if err != nil {
		return "", err
	}

	sess, ok := session.(*Session)
	if !ok {
		return "", errors.New("invalid session type")
	}

	s.Email = sess.Email
	// Result of Authorize is not used by gothic package
	return "", nil
}
