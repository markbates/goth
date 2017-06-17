package dropbox

import (
	httpmock "gopkg.in/jarcoal/httpmock.v1"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func provider() *Provider {
	return New(os.Getenv("DROPBOX_KEY"), os.Getenv("DROPBOX_SECRET"), "/foo", "email")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("DROPBOX_KEY"))
	a.Equal(p.Secret, os.Getenv("DROPBOX_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), provider())
}

func Test_ImplementsSession(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}
	a.Implements((*goth.Session)(nil), s)
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.BeginAuth("test_state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "www.dropbox.com/1/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://www.dropbox.com/1/oauth2/authorize","Token":"1234567890"}`)
	a.NoError(err)

	s := session.(*Session)
	a.Equal(s.AuthURL, "https://www.dropbox.com/1/oauth2/authorize")
	a.Equal(s.Token, "1234567890")
}

func Test_SessionToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","Token":""}`)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"
	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_SuccessfulRevoke(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", "https://api.dropbox.com/2/auth/token/revoke", httpmock.NewStringResponder(200, ""))

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

	httpmock.RegisterResponder("GET", "https://api.dropbox.com/2/auth/tooken/revoke", httpmock.NewStringResponder(400, ""))

	a := assert.New(t)

	provider := provider()
	s, err := provider.UnmarshalSession(`{"AccessToken":"1234567890"}`)
	a.NoError(err)
	err = provider.Revoke(s)
	a.Error(err)
}
