package logingov_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/logingov"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.IssuerId, os.Getenv("LOGINGOV_ISSUER_ID"))
	a.Equal(p.CallbackUrl, os.Getenv("LOGINGOV_REDIRECT_URI"))
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
	s := session.(*logingov.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "idp.int.identitysandbox.gov/openid_connect/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://idp.int.identitysandbox.gov/openid_connect/authorize","AccessToken":"123456789"}`)
	a.NoError(err)

	s := session.(*logingov.Session)
	a.Equal(s.AuthURL, "https://idp.int.identitysandbox.gov/openid_connect/authorize")
	a.Equal(s.AccessToken, "123456789")
}

func provider() *logingov.Provider {
	p, _ := logingov.New(os.Getenv("LOGINGOV_ISSUER_ID"), os.Getenv("LOGINGOV_REDIRECT_URI"), os.Getenv("LOGINGOV_AUTO_DISCOVERY_URL"))
	return p
}
