package stripe_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/stripe"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("STRIPE_KEY"))
	a.Equal(p.Secret, os.Getenv("STRIPE_SECRET"))
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
	s := session.(*stripe.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "connect.stripe.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://connect.stripe.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*stripe.Session)
	a.Equal(s.AuthURL, "https://connect.stripe.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *stripe.Provider {
	return stripe.New(os.Getenv("STRIPE_KEY"), os.Getenv("STRIPE_SECRET"), "/foo")
}
