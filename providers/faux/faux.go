// Package faux is used exclusive for testing purposes. I would strongly suggest you move along
// as there's nothing to see here.
package faux

import (
	"encoding/json"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/net/context"
)

// Provider is used only for testing.
type Provider struct {
}

// Session is used only for testing.
type Session struct {
	Name  string
	Email string
}

// Name is used only for testing.
func (p *Provider) Name() string {
	return "faux"
}

// BeginAuth is used only for testing.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{}, nil
}

// FetchUser is used only for testing.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	return goth.User{
		Name:  sess.Name,
		Email: sess.Email,
	}, nil
}

// UnmarshalSession is used only for testing.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}

// Debug is used only for testing.
func (p *Provider) Debug(debug bool) {}

// Authorize is used only for testing.
func (p *Session) Authorize(ctx context.Context, provider goth.Provider, params goth.Params) (string, error) {
	return "", nil
}

// Marshal is used only for testing.
func (p *Session) Marshal() string {
	b, _ := json.Marshal(p)
	return string(b)
}

// GetAuthURL is used only for testing.
func (p *Session) GetAuthURL() (string, error) {
	return "http://example.com/auth/", nil
}
