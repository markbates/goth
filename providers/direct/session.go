package direct

import (
	"encoding/json"
	"errors"

	"github.com/markbates/goth"
)

type DirectSession struct {
	AuthURL     string
	AccessToken string
	Email       string
}

func (s *DirectSession) GetAuthURL() (string, error) {
	return s.AuthURL, nil
}

func (s *DirectSession) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *DirectSession) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	email := params.Get("email")
	password := params.Get("password")

	directProvider, ok := provider.(*DirectProvider)
	if !ok {
		return "", errors.New("invalid provider type")
	}

	session, err := directProvider.IssueSession(email, password)
	if err != nil {
		return "", err
	}

	sess, ok := session.(*DirectSession)
	if !ok {
		return "", errors.New("invalid session type")
	}

	s.AccessToken = sess.AccessToken
	s.Email = sess.Email
	return sess.AccessToken, nil
}
