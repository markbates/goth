package yahoo_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/yahoo"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("YAHOO_KEY"))
	a.Equal(p.Secret, os.Getenv("YAHOO_SECRET"))
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
	s := session.(*yahoo.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "api.login.yahoo.com/oauth2/request_auth")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://api.login.yahoo.com/oauth2/request_auth","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*yahoo.Session)
	a.Equal(s.AuthURL, "https://api.login.yahoo.com/oauth2/request_auth")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *yahoo.Provider {
	return yahoo.New(os.Getenv("YAHOO_KEY"), os.Getenv("YAHOO_SECRET"), "/foo")
}
