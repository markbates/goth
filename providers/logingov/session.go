package logingov

import (
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"strings"
	"time"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with login.gov.
type Session struct {
	AuthURL      string
	AccessToken  string
	IdToken      string
	RefreshToken string
	ExpiresAt    time.Time
	CodeVerifier string
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the login.gov provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with login.gov and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", s.CodeVerifier),
	}
	token, err := p.cfg.Exchange(oauth2.NoContext, params.Get("code"), opts...)
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.IdToken = token.Extra("id_token").(string)
	s.ExpiresAt = token.Expiry

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

// UnmarshalSession wil unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}
