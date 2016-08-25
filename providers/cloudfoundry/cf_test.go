package cloudfoundry_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/cloudfoundry"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("UAA_CLIENT_ID"))
	a.Equal(p.Secret, os.Getenv("UAA_CLIENT_SECRET"))
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
	s := session.(*cloudfoundry.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://cf.example.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://cf.example.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*cloudfoundry.Session)
	a.Equal(s.AuthURL, "https://cf.example.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *cloudfoundry.Provider {
	return cloudfoundry.New("https://cf.example.com/", os.Getenv("UAA_CLIENT_ID"), os.Getenv("UAA_CLIENT_SECRET"), "/foo")
}
