package reverb

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with Reverb.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Reverb provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Reverb and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	if s == nil {
		return "", errors.New("reverb: session is nil")
	}
	if provider == nil {
		return "", errNilProvider
	}

	p, ok := provider.(*Provider)
	if !ok || p == nil {
		return "", errors.New("reverb: provider type is invalid")
	}

	if params == nil {
		return "", errors.New("reverb: params cannot be nil")
	}

	code := params.Get("code")
	if code == "" {
		return "", errors.New("reverb: authorization code is required")
	}

	if p.config == nil {
		return "", errNilOAuthConfig
	}

	token, err := p.config.Exchange(goth.ContextForClient(p.Client()), code)
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	return token.AccessToken, nil
}

// Marshal the session into a string.
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

// String is a string representation of the session.
func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}
