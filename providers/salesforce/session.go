package salesforce

import (
	"encoding/json"
	"errors"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"strings"
)

// Session stores data during the auth process with Salesforce.
// Expiry of access token is not provided by Salesforce, it is just controlled by timeout configured in auth2 settings
// by individual users
// Only way to check whether access token has expired or not is based on the response you receive if you try using
// access token and get some error
// Also, For salesforce refresh token to work follow these else remove scopes from here
//On salesforce.com, navigate to where you app is configured. (Setup > Create > Apps)
//Under Connected Apps, click on your application's name to view its settings, then click Edit.
//Under Selected OAuth Scopes, ensure that "Perform requests on your behalf at any time" is selected. You must include this even if you already chose "Full access".
//Save, then try your OAuth flow again. It make take a short while for the update to propagate.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ID           string //Required to get the user info from sales force
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Salesforce provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("an AuthURL has not be set")
	}
	return s.AuthURL, nil
}

// Authorize the session with Salesforce and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(oauth2.NoContext, params.Get("code"))

	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ID = token.Extra("id").(string) //Required to get the user info from sales force
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
