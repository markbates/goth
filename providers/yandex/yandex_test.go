package yandex_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/yandex"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("YANDEX_KEY"))
	a.Equal(p.Secret, os.Getenv("YANDEX_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_Name(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	a.Equal(p.Name(), "yandex")
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
	s := session.(*yandex.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://oauth.yandex.ru/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://oauth.yandex.ru/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*yandex.Session)
	a.Equal(s.AuthURL, "https://oauth.yandex.ru/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *yandex.Provider {
	return yandex.New(os.Getenv("YANDEX_KEY"), os.Getenv("YANDEX_SECRET"), "/foo")
}
