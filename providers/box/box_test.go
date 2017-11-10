package box_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/box"
	"github.com/stretchr/testify/assert"
	httpmock "gopkg.in/jarcoal/httpmock.v1"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("BOX_KEY"))
	a.Equal(p.Secret, os.Getenv("BOX_SECRET"))
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
	s := session.(*box.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "app.box.com/api/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://app.box.com/api/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*box.Session)
	a.Equal(s.AuthURL, "https://app.box.com/api/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *box.Provider {
	return box.New(os.Getenv("BOX_KEY"), os.Getenv("BOX_SECRET"), "/foo")
}

func Test_SuccessfulRevoke(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://api.box.com/oauth2/revoke", httpmock.NewStringResponder(200, ""))

	a := assert.New(t)

	provider := provider()
	s, err := provider.UnmarshalSession(`{"AuthURL":"https://api.box.com/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)
	err = provider.Revoke(s)
	a.NoError(err)
}

func Test_UnsuccessfulRevoke(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://api.box.com/oauth2/revoke", httpmock.NewStringResponder(400, ""))

	a := assert.New(t)

	provider := provider()
	s, err := provider.UnmarshalSession(`{"AuthURL":"https://api.box.com/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)
	err = provider.Revoke(s)
	a.Error(err)
}
