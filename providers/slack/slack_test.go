package slack_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/slack"
	"github.com/stretchr/testify/assert"
	httpmock "gopkg.in/jarcoal/httpmock.v1"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("SLACK_KEY"))
	a.Equal(p.Secret, os.Getenv("SLACK_SECRET"))
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
	s := session.(*slack.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "slack.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://slack.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*slack.Session)
	a.Equal(s.AuthURL, "https://slack.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *slack.Provider {
	return slack.New(os.Getenv("SLACK_KEY"), os.Getenv("SLACK_SECRET"), "/foo")
}

func Test_SuccessfulRevoke(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://slack.com/api/auth.revoke?token=1234567890", httpmock.NewStringResponder(200, `{"ok":true}`))

	a := assert.New(t)

	provider := provider()
	s, err := provider.UnmarshalSession(`{"AccessToken":"1234567890"}`)
	a.NoError(err)
	err = provider.Revoke(s)
	a.NoError(err)
}

func Test_UnsuccessfulRevoke(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://slack.com/api/auth.revoke?token=1234567890", httpmock.NewStringResponder(200, `{"ok":"false"}`))

	a := assert.New(t)

	provider := provider()
	s, err := provider.UnmarshalSession(`{"AccessToken":"1234567890"}`)
	a.NoError(err)
	err = provider.Revoke(s)
	a.Error(err)
}
