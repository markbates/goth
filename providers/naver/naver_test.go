package naver_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/naver"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("NAVER_KEY"))
	a.Equal(p.Secret, os.Getenv("NAVER_SECRET"))
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
	s := session.(*naver.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://nid.naver.com/oauth2.0/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("NAVER_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"ttps://nid.naver.com/oauth2.0/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*naver.Session)
	a.Equal(s.AuthURL, "ttps://nid.naver.com/oauth2.0/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *naver.Provider {
	return naver.New(os.Getenv("NAVER_KEY"), os.Getenv("NAVER_SECRET"), "/foo")
}
