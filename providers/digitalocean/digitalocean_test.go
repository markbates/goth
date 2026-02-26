package digitalocean_test

import (
	"fmt"
	"testing"

	"github.com/markbates/goth/providers/digitalocean"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := digitaloceanProvider()
	a.Equal(provider.ClientKey, "digitalocean_key")
	a.Equal(provider.Secret, "digitalocean_secret")
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := digitaloceanProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*digitalocean.Session)

	a.NoError(err)
	a.Contains(s.AuthURL, "cloud.digitalocean.com/v1/oauth/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", "digitalocean_key"))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=read")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := digitaloceanProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://github.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*digitalocean.Session)
	a.Equal(session.AuthURL, "http://github.com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func digitaloceanProvider() *digitalocean.Provider {
	return digitalocean.New("digitalocean_key", "digitalocean_secret", "/foo", "read")
}
