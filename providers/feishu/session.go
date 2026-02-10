package feishu

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/markbates/goth"
)

type Session struct {
	AuthURL               string
	AccessToken           string
	RefreshToken          string
	ExpiresAt             time.Time
	RefreshTokenExpiresAt time.Time
}

func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
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

	refreshTokenExpiresAt := token.Extra("refresh_token_expires_in")
	if refreshTokenExpiresAt2, ok := refreshTokenExpiresAt.(int); ok {
		s.RefreshTokenExpiresAt = time.Now().Add(time.Second * time.Duration(refreshTokenExpiresAt2))
	}

	return token.AccessToken, err
}
