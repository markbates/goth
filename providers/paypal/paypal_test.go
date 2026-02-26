package paypal_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/paypal"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("PAYPAL_KEY"))
	a.Equal(p.Secret, os.Getenv("PAYPAL_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := urlCustomisedURLProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*paypal.Session)
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
	s := session.(*paypal.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "paypal.com/webapps/auth/protocol/openidconnect/v1/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*paypal.Session)
	a.Equal(s.AuthURL, "https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *paypal.Provider {
	return paypal.New(os.Getenv("PAYPAL_KEY"), os.Getenv("PAYPAL_SECRET"), "/foo")
}

func urlCustomisedURLProvider() *paypal.Provider {
	return paypal.NewCustomisedURL(os.Getenv("PAYPAL_KEY"), os.Getenv("PAYPAL_SECRET"), "/foo", "http://authURL", "http://tokenURL", "http://profileURL")
}
