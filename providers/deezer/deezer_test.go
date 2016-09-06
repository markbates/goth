package deezer_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/deezer"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := deezerProvider()
	a.Equal(provider.ClientKey, os.Getenv("DEEZER_KEY"))
	a.Equal(provider.Secret, os.Getenv("DEEZER_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), deezerProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := deezerProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*deezer.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://connect.deezer.com/oauth/auth.php")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := deezerProvider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://connect.deezer.com/oauth/auth.php","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*deezer.Session)
	a.Equal(s.AuthURL, "https://connect.deezer.com/oauth/auth.php")
	a.Equal(s.AccessToken, "1234567890")
}

func deezerProvider() *deezer.Provider {
	return deezer.New(os.Getenv("DEEZER_KEY"), os.Getenv("DEEZER_SECRET"), "/foo", "email")
}
