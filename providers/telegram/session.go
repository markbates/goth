package telegram

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// Session stores data during the auth process with Telegram.
type Session struct {
	AuthURL      string
	CodeVerifier string
	State        string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	IDToken      string
	User         goth.User
}

// GetAuthURL will return the URL set by calling BeginAuth on the Telegram provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Telegram and store the retrieved user information.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	if params.Get("state") != s.State {
		return "", errors.New("invalid telegram state")
	}

	token, err := p.config.Exchange(goth.ContextForClient(p.Client()), params.Get("code"), oauth2.VerifierOption(s.CodeVerifier))
	if err != nil {
		return "", err
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return "", errors.New("telegram id_token is empty")
	}
	parsed, err := parseIDToken(goth.ContextForClient(p.Client()), p.Client(), idToken, p.config.ClientID)
	if err != nil {
		return "", err
	}
	user, err := userFromClaims(parsed)
	if err != nil {
		return "", err
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	s.IDToken = idToken
	s.User = user
	return token.AccessToken, nil
}

// Marshal the session into a string.
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
