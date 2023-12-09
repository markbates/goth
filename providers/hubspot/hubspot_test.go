package hubspot_test

import (
	"github.com/markbates/goth/providers/hubspot"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("HUBSPOT_KEY"))
	a.Equal(p.Secret, os.Getenv("HUBSPOT_SECRET"))
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
	s := session.(*hubspot.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://app.hubspot.com/oauth/authoriz")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://app.hubspot.com/oauth/authoriz","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*hubspot.Session)
	a.Equal(s.AuthURL, "https://app.hubspot.com/oauth/authoriz")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *hubspot.Provider {
	return hubspot.New(os.Getenv("HUBSPOT_KEY"), os.Getenv("HUBSPOT_SECRET"), "/foo")
}
