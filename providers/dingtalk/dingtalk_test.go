package dingtalk_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/dingtalk"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("DINGTALK_KEY"))
	a.Equal(p.Secret, os.Getenv("DINGTALK_SECRET"))
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
	s := session.(*dingtalk.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "login.dingtalk.com/oauth2/auth")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://login.dingtalk.com/oauth2/auth","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*dingtalk.Session)
	a.Equal(s.AuthURL, "https://login.dingtalk.com/oauth2/auth")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *dingtalk.Provider {
	return dingtalk.New(os.Getenv("DINGTALK_KEY"), os.Getenv("DINGTALK_SECRET"), "/foo", os.Getenv("DINGTALK_CORP_ID"))
}
