package livechat

import (
	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("LIVECHAT_KEY"))
	a.Equal(p.Secret, os.Getenv("LIVECHAT_SECRET"))
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
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "accounts.livechat.com")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://accounts.livechat.com","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*Session)
	a.Equal(s.AuthURL, "https://accounts.livechat.com")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *Provider {
	return New(os.Getenv("LIVECHAT_KEY"), os.Getenv("LIVECHAT_SECRET"), "/foo")
}
