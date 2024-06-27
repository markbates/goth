package strava_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/strava"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := stravaProvider()
	a.Equal(provider.ClientKey, os.Getenv("STRAVA_KEY"))
	a.Equal(provider.Secret, os.Getenv("STRAVA_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), stravaProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := stravaProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*strava.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "www.strava.com/oauth/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("STRAVA_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=read")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := stravaProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://www.strava.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*strava.Session)
	a.Equal(session.AuthURL, "https://www.strava.com/oauth/authorize")
	a.Equal(session.AccessToken, "1234567890")
}

func stravaProvider() *strava.Provider {
	return strava.New(os.Getenv("STRAVA_KEY"), os.Getenv("STRAVA_SECRET"), "/foo", "read")
}
