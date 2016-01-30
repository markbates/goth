package instagram_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/instagram"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := instagramProvider()
	a.Equal(provider.ClientKey, os.Getenv("INSTAGRAM_KEY"))
	a.Equal(provider.Secret, os.Getenv("INSTAGRAM_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), instagramProvider())
}
func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	provider := instagramProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*instagram.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "api.instagram.com/oauth/authorize/")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("INSTAGRAM_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=basic")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := instagramProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://api.instagram.com/oauth/authorize/","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*instagram.Session)
	a.Equal(session.AuthURL, "https://api.instagram.com/oauth/authorize/")
	a.Equal(session.AccessToken, "1234567890")
}

func instagramProvider() *instagram.Provider {
	return instagram.New(os.Getenv("INSTAGRAM_KEY"), os.Getenv("INSTAGRAM_SECRET"), "/foo", "basic")
}
