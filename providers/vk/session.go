package vk

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with VK.
type Session struct {
	AuthURL     string
	AccessToken string
	ExpiresAt   time.Time
	email       string
}

// GetAuthURL returns the URL for the authentication end-point for the provider.
func (s *Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Marshal the session into a string
func (s *Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Authorize the session with VK and return the access token to be stored for future use.
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
	s.ExpiresAt = token.Expiry
	// VK returns "email" as a top-level field in the token response only when the
	// user has an email set in their profile AND has granted the email scope.
	// Accounts registered without an email (allowed by VK since ~2018) omit it,
	// so treat it as optional rather than failing the entire login flow (#338).
	if email, ok := token.Extra("email").(string); ok {
		s.email = email
	}
	return s.AccessToken, err
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := new(Session)
	err := json.NewDecoder(strings.NewReader(data)).Decode(&sess)
	return sess, err
}
