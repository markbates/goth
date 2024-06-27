package kakao_test

import (
	"os"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/kakao"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("KAKAO_CLIENT_ID"))
	a.Equal(p.Secret, os.Getenv("KAKAO_CLIENT_SECRET"))
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
	s := session.(*kakao.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://kauth.kakao.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://kauth.kakao.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*kakao.Session)
	a.Equal(s.AuthURL, "https://kauth.kakao.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *kakao.Provider {
	return kakao.New(os.Getenv("KAKAO_CLIENT_ID"), os.Getenv("KAKAO_CLIENT_SECRET"), "/foo")
}
