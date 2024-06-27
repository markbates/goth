// session.go
package email

import (
	"encoding/json"
	"errors"

	"github.com/Avyukth/goth"
)

// Session stores data during the auth process with Email.
type Session struct {
	Email string
}

// GetAuthURL is not used for email authentication
func (s *Session) GetAuthURL() (string, error) {
	return "", errors.New("GetAuthURL is not supported for Email sessions")
}

// Authorize the session with Email and return the email address to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	s.Email = params.Get("email")
	return s.Email, p.SendVerificationEmail(s.Email)
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
	err := json.Unmarshal([]byte(data), s)
	return s, err
}
