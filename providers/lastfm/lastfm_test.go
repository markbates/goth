package lastfm

import (
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := lastfmProvider()
	a.Equal(provider.ClientKey, os.Getenv("LASTFM_KEY"))
	a.Equal(provider.Secret, os.Getenv("LASTFM_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), lastfmProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := lastfmProvider()
	session, err := provider.BeginAuth("")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "www.lastfm.com.br/api/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("api_key=%s", os.Getenv("LASTFM_KEY")))
	a.Contains(s.AuthURL, fmt.Sprintf("callback=%s", url.QueryEscape("/foo")))
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := lastfmProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://com/auth_url","AccessToken":"123456", "Login":"Quin"}`)
	a.NoError(err)
	session := s.(*Session)
	a.Equal(session.AuthURL, "http://com/auth_url")
	a.Equal(session.AccessToken, "123456")
	a.Equal(session.Login, "Quin")
}

func lastfmProvider() *Provider {
	return New(os.Getenv("LASTFM_KEY"), os.Getenv("LASTFM_SECRET"), "/foo")
}
