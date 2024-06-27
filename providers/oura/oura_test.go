package oura_test

import (
	"os"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/oura"
	"github.com/stretchr/testify/assert"
)

func provider() *oura.Provider {
	return oura.New(os.Getenv("OURA_KEY"), os.Getenv("OURA_SECRET"), "/foo", "user")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("OURA_KEY"))
	a.Equal(p.Secret, os.Getenv("OURA_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_ImplementsProvider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*oura.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://cloud.ouraring.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://cloud.ouraring.com/oauth/authorize","AccessToken":"1234567890","UserID":"abc"}`)
	a.NoError(err)

	s := session.(*oura.Session)
	a.Equal(s.AuthURL, "https://cloud.ouraring.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
	a.Equal(s.UserID, "abc")
}
