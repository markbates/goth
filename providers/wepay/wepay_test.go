package wepay_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/wepay"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("WEPAY_KEY"))
	a.Equal(p.Secret, os.Getenv("WEPAY_SECRET"))
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
	s := session.(*wepay.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "www.wepay.com/v2/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://www.wepay.com/v2/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*wepay.Session)
	a.Equal(s.AuthURL, "https://www.wepay.com/v2/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *wepay.Provider {
	return wepay.New(os.Getenv("WEPAY_KEY"), os.Getenv("WEPAY_SECRET"), "/foo")
}
