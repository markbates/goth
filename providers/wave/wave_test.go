package wave_test

import (
	"github.com/overlay-labs/goth"
	"github.com/overlay-labs/goth/providers/wave"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("WAVE_KEY"))
	a.Equal(p.Secret, os.Getenv("WAVE_SECRET"))
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
	s := session.(*wave.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://api.waveapps.com/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://api.waveapps.com/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*wave.Session)
	a.Equal(s.AuthURL, "https://api.waveapps.com/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *wave.Provider {
	return wave.New(os.Getenv("WAVE_KEY"), os.Getenv("WAVE_SECRET"), "/foo")
}
