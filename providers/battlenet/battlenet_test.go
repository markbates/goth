package battlenet_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/battlenet"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("BATTLENET_KEY"))
	a.Equal(p.Secret, os.Getenv("BATTLENET_SECRET"))
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
	s := session.(*battlenet.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "us.battle.net/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://us.battle.net/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*battlenet.Session)
	a.Equal(s.AuthURL, "https://us.battle.net/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *battlenet.Provider {
	return battlenet.New(os.Getenv("BATTLENET_KEY"), os.Getenv("BATTLENET_SECRET"), "/foo")
}
