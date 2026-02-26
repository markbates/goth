package nextcloud_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/nextcloud"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("NEXTCLOUD_KEY"))
	a.Equal(p.Secret, os.Getenv("NEXTCLOUD_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := urlCustomisedURLProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*nextcloud.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "http://authURL")
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
	s := session.(*nextcloud.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "/apps/oauth2/authorize?client_id=")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://nextcloud.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*nextcloud.Session)
	a.Equal(s.AuthURL, "https://nextcloud.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *nextcloud.Provider {
	return nextcloud.NewCustomisedDNS(
		os.Getenv("NEXTCLOUD_KEY"),
		os.Getenv("NEXTCLOUD_SECRET"),
		"/foo",
		os.Getenv("NEXTCLOUD_DNS"),
	)
}

func urlCustomisedURLProvider() *nextcloud.Provider {
	return nextcloud.NewCustomisedURL(os.Getenv("NEXTCLOUD_KEY"), os.Getenv("NEXTCLOUD_SECRET"), "/foo", "http://authURL", "http://tokenURL", "http://profileURL")
}
