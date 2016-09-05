package intercom_test

import (
	"fmt"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/intercom"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := intercomProvider()
	a.Equal(provider.ClientKey, os.Getenv("INTERCOM_KEY"))
	a.Equal(provider.Secret, os.Getenv("INTERCOM_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), intercomProvider())
}
func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	provider := intercomProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*intercom.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://app.intercom.io/oauth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("INTERCOM_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := intercomProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://app.intercom.io/oauth","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*intercom.Session)
	a.Equal(session.AuthURL, "https://app.intercom.io/oauth")
	a.Equal(session.AccessToken, "1234567890")
}

func intercomProvider() *intercom.Provider {
	return intercom.New(os.Getenv("INTERCOM_KEY"), os.Getenv("INTERCOM_SECRET"), "/foo", "basic")
}
