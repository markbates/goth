package azuredevops_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/azuredevops"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := azureProvider()
	a.Equal(provider.ClientKey, os.Getenv("AZUREDEVOPS_KEY"))
	a.Equal(provider.Secret, os.Getenv("AZUREDEVOPS_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), azureProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := azureProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*azuredevops.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://app.vssps.visualstudio.com/oauth2/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("AZUREDEVOPS_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=user")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := azureProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://app.vssps.visualstudio.com/oauth2/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*azuredevops.Session)
	a.Equal(session.AuthURL, "https://app.vssps.visualstudio.com/oauth2/authorize")
	a.Equal(session.AccessToken, "1234567890")
}

func azureProvider() *azuredevops.Provider {
	return azuredevops.New(os.Getenv("AZUREDEVOPS_KEY"), os.Getenv("AZUREDEVOPS_SECRET"), "/foo", "user")
}
