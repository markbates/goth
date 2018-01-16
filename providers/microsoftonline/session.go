package microsoftonline

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io/ioutil"
	"strings"
	"time"

	"github.com/markbates/goth"
)

// Session is the implementation of `goth.Session` for accessing microsoftonline.
// Refresh token not available for microsoft online: session size hit the limit of max cookie size
type Session struct {
	AuthURL     string
	AccessToken string
	ExpiresAt   time.Time
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Facebook provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}

	return s.AuthURL, nil
}

// Authorize the session with Facebook and return the access token to be stored for future use.
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

	return token.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	data, _ := json.Marshal(s)

	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(data)); err != nil {
		panic(err)
	}
	if err := gz.Flush(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return b.String()
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession wil unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	session := &Session{}

	rdata := strings.NewReader(data)
	r, err := gzip.NewReader(rdata)
	if err != nil {
		return session, err
	}
	s, err := ioutil.ReadAll(r)
	if err != nil {
		return session, err
	}

	err = json.NewDecoder(bytes.NewReader(s)).Decode(session)
	return session, err
}
