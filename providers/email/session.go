package email

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/Avyukth/goth"
)

// Session stores data during the auth process with Email.
type Session struct {
	AuthURL string
	Email   string
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Email provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Email and return the email address to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	email := p.config.NormalizeIdentifier(params.Get("email"))
	token := params.Get("token")

	// Here you would typically verify the token
	// For this example, we'll just assume it's valid if it's not empty
	if token == "" {
		return "", errors.New("Invalid or missing token")
	}

	s.Email = email
	return email, nil
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}
