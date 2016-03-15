package uber_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/uber"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("UBER_KEY"))
	a.Equal(p.Secret, os.Getenv("UBER_SECRET"))
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
	s := session.(*uber.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "login.uber.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://login.uber.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*uber.Session)
	a.Equal(s.AuthURL, "https://login.uber.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *uber.Provider {
	return uber.New(os.Getenv("UBER_KEY"), os.Getenv("UBER_SECRET"), "/foo")
}
