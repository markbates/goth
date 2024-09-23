package neurodyne_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/neurodyne"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("NEURODYNE_KEY"))
	a.Equal(p.Secret, os.Getenv("NEURODYNE_SECRET"))
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
	s := session.(*neurodyne.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "id.nws.neurodyne.pro/oauth2/auth")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://id.nws.neurodyne.pro/oauth2/auth","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*neurodyne.Session)
	a.Equal(s.AuthURL, "https://id.nws.neurodyne.pro/oauth2/auth")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *neurodyne.Provider {
	return neurodyne.New(os.Getenv("NEURODYNE_KEY"), os.Getenv("NEURODYNE_SECRET"), "/foo")
}
