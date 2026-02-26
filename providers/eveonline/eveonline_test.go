package eveonline_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/eveonline"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("EVEONLINE_KEY"))
	a.Equal(p.Secret, os.Getenv("EVEONLINE_SECRET"))
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
	s := session.(*eveonline.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "login.eveonline.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://login.eveonline.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*eveonline.Session)
	a.Equal(s.AuthURL, "https://login.eveonline.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *eveonline.Provider {
	return eveonline.New(os.Getenv("EVEONLINE_KEY"), os.Getenv("EVEONLINE_SECRET"), "/foo")
}
