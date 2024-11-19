package zoom

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// Session stores data during the auth process with Zoom.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Zoom provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Zoom and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)

	var authParams []oauth2.AuthCodeOption

	// override redirect_uri if passed as param
	redirectURL := params.Get("redirect_uri")
	if redirectURL != "" {
		authParams = append(authParams, oauth2.SetAuthURLParam("redirect_uri", redirectURL))
	}

	// set code_verifier if passed as param
	codeVerifier := params.Get("code_verifier")
	if codeVerifier != "" {
		authParams = append(authParams, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	}

	token, err := p.config.Exchange(goth.ContextForClient(p.Client()), params.Get("code"), authParams...)

	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
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

func (p *Provider) CreateSession(sessionValue interface{}) (goth.Session, error) {
	return &Session{}, errors.New("not implemented")
}
