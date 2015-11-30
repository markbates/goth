package gplus_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/smagic39/goth"
	"github.com/smagic39/goth/providers/gplus"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := gplusProvider()
	a.Equal(provider.ClientKey, os.Getenv("GPLUS_KEY"))
	a.Equal(provider.Secret, os.Getenv("GPLUS_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := gplusProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*gplus.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "accounts.google.com/o/oauth2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("GPLUS_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=profile+email+openid")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), gplusProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := gplusProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://accounts.google.com/o/oauth2/auth","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*gplus.Session)
	a.Equal(session.AuthURL, "https://accounts.google.com/o/oauth2/auth")
	a.Equal(session.AccessToken, "1234567890")
}

func gplusProvider() *gplus.Provider {
	return gplus.New(os.Getenv("GPLUS_KEY"), os.Getenv("GPLUS_SECRET"), "/foo")
}
