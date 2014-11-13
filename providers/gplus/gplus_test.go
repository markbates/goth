package gplus

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := facebookProvider()
	a.Equal(provider.ClientKey, os.Getenv("GPLUS_KEY"))
	a.Equal(provider.Secret, os.Getenv("GPLUS_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
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
	session := s.(*facebook.Session)
	a.Equal(session.AuthURL, "https://accounts.google.com/o/oauth2/auth")
	a.Equal(session.AccessToken, "1234567890")
}

func gplusProvider() *facebook.Provider {
	return New(os.Getenv("GPLUS_KEY"), os.Getenv("GPLUS_SECRET"), "/foo")
}
