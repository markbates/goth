package facebook_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/facebook"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := facebookProvider()
	a.Equal(provider.ClientKey, os.Getenv("FACEBOOK_KEY"))
	a.Equal(provider.Secret, os.Getenv("FACEBOOK_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), facebookProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := facebookProvider()
	session, err := provider.BeginAuth()
	s := session.(*facebook.Session)
	a.NoError(err)
	a.Equal(s.AuthURL, fmt.Sprintf("https://www.facebook.com/dialog/oauth?client_id=%s&redirect_uri=%%2Ffoo&response_type=code&state=state", provider.ClientKey))
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := facebookProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://facebook.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*facebook.Session)
	a.Equal(session.AuthURL, "http://facebook.com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func facebookProvider() *facebook.Provider {
	return facebook.New(os.Getenv("FACEBOOK_KEY"), os.Getenv("FACEBOOK_SECRET"), "/foo")
}
