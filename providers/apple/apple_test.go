package apple

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientId(), os.Getenv("APPLE_KEY"))
	a.Equal(p.Secret(), os.Getenv("APPLE_SECRET"))
	a.Equal(p.RedirectURL(), "/foo")
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
	a.Contains(s.AuthURL, "appleid.apple.com/auth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://appleid.apple.com/auth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*Session)
	a.Equal(s.AuthURL, "https://appleid.apple.com/auth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *Provider {
	return New(os.Getenv("APPLE_KEY"), os.Getenv("APPLE_SECRET"), "/foo", nil)
}
