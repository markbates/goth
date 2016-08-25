package onedrive_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/onedrive"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("ONEDRIVE_KEY"))
	a.Equal(p.Secret, os.Getenv("ONEDRIVE_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*onedrive.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "login.live.com/oauth20_authorize.srf")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://login.live.com/oauth20_authorize.srf","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*onedrive.Session)
	a.Equal(s.AuthURL, "https://login.live.com/oauth20_authorize.srf")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *onedrive.Provider {
	return onedrive.New(os.Getenv("ONEDRIVE_KEY"), os.Getenv("ONEDRIVE_SECRET"), "/foo")
}
