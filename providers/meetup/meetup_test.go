package meetup_test

import (
	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"github.com/markbates/goth/providers/meetup"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("MEETUP_KEY"))
	a.Equal(p.Secret, os.Getenv("MEETUP_SECRET"))
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
	s := session.(*meetup.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://secure.meetup.com/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"ttps://secure.meetup.com/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*meetup.Session)
	a.Equal(s.AuthURL, "ttps://secure.meetup.com/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *meetup.Provider {
	return meetup.New(os.Getenv("MEETUP_KEY"), os.Getenv("MEETUP_SECRET"), "/foo")
}
