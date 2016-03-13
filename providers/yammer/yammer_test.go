package yammer_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/yammer"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("YAMMER_KEY"))
	a.Equal(p.Secret, os.Getenv("YAMMER_SECRET"))
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
	s := session.(*yammer.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "www.yammer.com/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://www.yammer.com/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*yammer.Session)
	a.Equal(s.AuthURL, "https://www.yammer.com/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *yammer.Provider {
	return yammer.New(os.Getenv("YAMMER_KEY"), os.Getenv("YAMMER_SECRET"), "/foo")
}
