package salesforce_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/salesforce"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("SALESFORCE_KEY"))
	a.Equal(p.Secret, os.Getenv("SALESFORCE_SECRET"))
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
	s := session.(*salesforce.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "login.salesforce.com/services/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://login.salesforce.com/services/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*salesforce.Session)
	a.Equal(s.AuthURL, "https://login.salesforce.com/services/oauth2/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *salesforce.Provider {
	return salesforce.New(os.Getenv("SALESFORCE_KEY"), os.Getenv("SALESFORCE_SECRET"), "/foo")
}
