package tiktok_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/tiktok"
	"github.com/stretchr/testify/assert"
)

const callbackURL = "/tests/for/the/win"

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("tiktok_KEY"))
	a.Equal(p.ClientSecret, os.Getenv("tiktok_SECRET"))
	a.Nil(p.Client)
	a.Equal(p.CallbackURL, callbackURL)
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
	s := session.(*tiktok.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://open-api.tiktok.com/platform/oauth/connect")
	a.Contains(s.AuthURL, fmt.Sprintf("%s%%2C%s", tiktok.ScopeUserInfoBasic, tiktok.ScopeVideoList))
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://open-api.tiktok.com/platform/oauth/connect","AccessToken":"1234567890"}"`)
	a.NoError(err)

	s := session.(*tiktok.Session)
	a.Equal(s.AuthURL, "https://open-api.tiktok.com/platform/oauth/connect")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *tiktok.Provider {
	p := tiktok.New(os.Getenv("tiktok_KEY"), os.Getenv("tiktok_SECRET"), callbackURL, tiktok.ScopeVideoList)
	return p
}
