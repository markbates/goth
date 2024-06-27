package facebook_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/facebook"
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
	session, err := provider.BeginAuth("test_state")
	s := session.(*facebook.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "facebook.com/dialog/oauth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("FACEBOOK_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=email")
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

func Test_SetCustomFields(t *testing.T) {
	t.Parallel()
	defaultFields := "email,first_name,last_name,link,about,id,name,picture,location"
	cf := []string{"email", "picture.type(large)"}
	a := assert.New(t)

	provider := facebookProvider()
	a.Equal(provider.Fields, defaultFields)
	provider.SetCustomFields(cf)
	a.Equal(provider.Fields, strings.Join(cf, ","))
}

func facebookProvider() *facebook.Provider {
	return facebook.New(os.Getenv("FACEBOOK_KEY"), os.Getenv("FACEBOOK_SECRET"), "/foo", "email")
}
