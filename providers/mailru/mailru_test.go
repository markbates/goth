package mailru_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/mailru"
	"github.com/stretchr/testify/assert"
)

func Test_Name(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := mailruProvider()
	a.Equal(provider.Name(), "mailru")
}

func Test_SetName(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := mailruProvider()
	provider.SetName("foo")
	a.Equal(provider.Name(), "foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), mailruProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := mailruProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*mailru.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "connect.mail.ru/oauth/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("MAILRU_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=photos")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := mailruProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://mailru.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*mailru.Session)
	a.Equal(session.AuthURL, "http://mailru.com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func mailruProvider() *mailru.Provider {
	return mailru.New(os.Getenv("MAILRU_KEY"), os.Getenv("MAILRU_SECRET"), "/foo", "photos")
}
