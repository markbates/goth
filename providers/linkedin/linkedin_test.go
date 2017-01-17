package linkedin_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/linkedin"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := linkedinProvider()
	a.Equal(provider.ClientKey, os.Getenv("LINKEDIN_KEY"))
	a.Equal(provider.Secret, os.Getenv("LINKEDIN_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), linkedinProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := linkedinProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*linkedin.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "linkedin.com/oauth/v2/authorization")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("LINKEDIN_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=r_basicprofile+r_emailaddress&state")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := linkedinProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://linkedin.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*linkedin.Session)
	a.Equal(session.AuthURL, "http://linkedin.com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func linkedinProvider() *linkedin.Provider {
	return linkedin.New(os.Getenv("LINKEDIN_KEY"), os.Getenv("LINKEDIN_SECRET"), "/foo", "r_basicprofile", "r_emailaddress")
}
