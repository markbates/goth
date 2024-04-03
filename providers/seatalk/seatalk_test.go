package seatalk_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/seatalk"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("SEATALK_KEY"))
	a.Equal(p.Secret, os.Getenv("SEATALK_SECRET"))
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
	s := session.(*seatalk.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "seatalkweb.com/webapp/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://seatalkweb.com/webapp/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*seatalk.Session)
	a.Equal(s.AuthURL, "https://seatalkweb.com/webapp/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *seatalk.Provider {
	return seatalk.New(os.Getenv("SEATALK_KEY"), os.Getenv("SEATALK_SECRET"), "/foo")
}
