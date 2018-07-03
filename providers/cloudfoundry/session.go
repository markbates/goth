package cloudfoundry

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// Session stores data during the auth process with Cloud Foundry.
type Session struct {
	AuthURL      string
	TokenType    string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Cloud Foundry provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("an AuthURL has not be set")
	}
	return s.AuthURL, nil
}

// Authorize the session with Cloud Foundry and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	ctx := context.WithValue(goth.ContextForClient(p.Client()), oauth2.HTTPClient, p.Client())
	token, err := p.config.Exchange(ctx, params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.TokenType = token.TokenType
	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
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
