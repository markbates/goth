package twitch

import (
	httpmock "gopkg.in/jarcoal/httpmock.v1"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func provider() *Provider {
	return New(os.Getenv("TWITCH_KEY"),
		os.Getenv("TWITCH_SECRET"), "/foo", "user")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("TWITCH_KEY"))
	a.Equal(p.Secret, os.Getenv("TWITCH_SECRET"))
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
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "api.twitch.tv/kraken/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://api.twitch.tv/kraken/oauth2/authorize", "AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*Session)
	a.Equal(s.AuthURL, "https://api.twitch.tv/kraken/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func Test_SuccessfulRevoke(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://api.twitch.tv/kraken/oauth2/revoke?client_id=&token=1234567890", httpmock.NewStringResponder(200, ""))

	a := assert.New(t)

	provider := provider()
	s, err := provider.UnmarshalSession(`{"AuthURL":"https://api.twitch.tv/kraken/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)
	err = provider.Revoke(s)
	a.NoError(err)
}

func Test_UnsuccessfulRevoke(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://api.twitch.tv/kraken/oauth2/revoke?client_id=&token=123456789", httpmock.NewStringResponder(400, ""))

	a := assert.New(t)

	provider := provider()
	s, err := provider.UnmarshalSession(`{"AuthURL":"https://api.twitch.tv/kraken/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)
	err = provider.Revoke(s)
	a.Error(err)
}
