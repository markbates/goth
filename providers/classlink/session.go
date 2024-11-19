package classlink

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/markbates/goth"
)

type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

func (s *Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

func (s *Session) Marshal() string {
	bytes, _ := json.Marshal(s)
	return string(bytes)
}

func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(goth.ContextForClient(p.Client()), params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	return token.AccessToken, err
}

func (s *Session) String() string {
	return s.Marshal()
}

func (p *Provider) CreateSession(sessionValue interface{}) (goth.Session, error) {
	return &Session{}, errors.New("not implemented")
}
