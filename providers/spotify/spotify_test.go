package spotify_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/spotify"
	"github.com/stretchr/testify/assert"
)

func provider() *spotify.Provider {
	return spotify.New(os.Getenv("SPOTIFY_KEY"), os.Getenv("SPOTIFY_SECRET"), "/foo", "user")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("SPOTIFY_KEY"))
	a.Equal(p.Secret, os.Getenv("SPOTIFY_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_ImplementsProvider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*spotify.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "accounts.spotify.com/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"http://accounts.spotify.com/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*spotify.Session)
	a.Equal(s.AuthURL, "http://accounts.spotify.com/authorize")
	a.Equal(s.AccessToken, "1234567890")
}
