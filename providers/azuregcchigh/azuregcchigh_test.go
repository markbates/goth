package azuregcchigh_test

import (
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/azuregcchigh"
	"github.com/stretchr/testify/assert"
)

const (
	applicationID = "6731de76-14a6-49ae-97bc-6eba6914391e"
	secret        = "foo"
	redirectUri   = "https://localhost:3000"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	provider := azureadProvider()

	a.Equal(provider.Name(), "azuregcchigh")
	a.Equal(provider.ClientKey, applicationID)
	a.Equal(provider.Secret, secret)
	a.Equal(provider.CallbackURL, redirectUri)
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := azureadProvider()
	a.Implements((*goth.Provider)(nil), p)
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	provider := azureadProvider()
	session, err := provider.BeginAuth("test_state")
	a.NoError(err)
	s := session.(*azuregcchigh.Session)
	a.Contains(s.AuthURL, "login.microsoftonline.us/common/oauth2/v2.0/authorize")
	a.Contains(s.AuthURL, "redirect_uri=https%3A%2F%2Flocalhost%3A3000")
	a.Contains(s.AuthURL, "scope=openid+profile+email")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := azureadProvider()
	session, err := provider.UnmarshalSession(`{"au":"http://foo","at":"1234567890"}`)
	a.NoError(err)

	s := session.(*azuregcchigh.Session)
	a.Equal(s.AuthURL, "http://foo")
	a.Equal(s.AccessToken, "1234567890")
}

func azureadProvider() *azuregcchigh.Provider {
	return azuregcchigh.New(applicationID, secret, redirectUri, azuregcchigh.ProviderOptions{})
}
