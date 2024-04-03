package cognito

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/okta"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("COGNITO_ID"))
	a.Equal(p.Secret, os.Getenv("COGNITO_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := urlCustomisedURLProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*okta.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "http://authURL")
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
	s := session.(*okta.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, os.Getenv("COGNITO_ISSUER_URL"))
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"` + os.Getenv("COGNITO_ISSUER_URL") + `/oauth2/authorize", "AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*okta.Session)
	a.Equal(s.AuthURL, os.Getenv("COGNITO_ISSUER_URL")+"/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *okta.Provider {
	return okta.New(os.Getenv("COGNITO_ID"), os.Getenv("COGNITO_SECRET"), os.Getenv("COGNITO_ISSUER_URL"), "/foo")
}

func urlCustomisedURLProvider() *okta.Provider {
	return okta.NewCustomisedURL(os.Getenv("CLIENT_ID"), os.Getenv("CLIENT_SECRET"), "/foo", "http://authURL", "http://tokenURL", "http://issuerURL", "http://profileURL")
}
