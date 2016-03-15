package soundcloud_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/soundcloud"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("SOUNDCLOUD_KEY"))
	a.Equal(p.Secret, os.Getenv("SOUNDCLOUD_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
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
	s := session.(*soundcloud.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "soundcloud.com/connect")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://soundcloud.com/connect","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*soundcloud.Session)
	a.Equal(s.AuthURL, "https://soundcloud.com/connect")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *soundcloud.Provider {
	return soundcloud.New(os.Getenv("SOUNDCLOUD_KEY"), os.Getenv("SOUNDCLOUD_SECRET"), "/foo")
}
