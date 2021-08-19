package classlink_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/classlink"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := classLinkProvider()
	a.Equal(provider.ClientKey, os.Getenv("CLASSLINK_KEY"))
	a.Equal(provider.ClientSecret, os.Getenv("CLASSLINK_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := classLinkProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*classlink.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "launchpad.classlink.com/oauth2/v2/")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("GOOGLE_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=profile")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), classLinkProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := classLinkProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://launchpad.classlink.com/oauth2/v2/","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*classlink.Session)
	a.Equal(session.AuthURL, "https://launchpad.classlink.com/oauth2/v2/")
	a.Equal(session.AccessToken, "1234567890")
}

func classLinkProvider() *classlink.Provider {
	return classlink.New(os.Getenv("CLASSLINK_KEY"), os.Getenv("CLASSLINK_SECRET"), "/foo")
}