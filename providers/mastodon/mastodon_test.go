package mastodon_test

import (
	"os"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/mastodon"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("MASTODON_KEY"))
	a.Equal(p.Secret, os.Getenv("MASTODON_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := urlCustomisedURLProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*mastodon.Session)
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
	s := session.(*mastodon.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "mastodon.social/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://mastodon.social/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*mastodon.Session)
	a.Equal(s.AuthURL, "https://mastodon.social/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *mastodon.Provider {
	return mastodon.New(os.Getenv("MASTODON_KEY"), os.Getenv("MASTODON_SECRET"), "/foo")
}

func urlCustomisedURLProvider() *mastodon.Provider {
	return mastodon.NewCustomisedURL(os.Getenv("MASTODON_KEY"), os.Getenv("MASTODON_SECRET"), "/foo", "http://authURL", "http://tokenURL", "http://profileURL")
}
