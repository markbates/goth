package bitbucket_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/bitbucket"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := bitbucketProvider()
	a.Equal(provider.ClientKey, os.Getenv("BITBUCKET_KEY"))
	a.Equal(provider.Secret, os.Getenv("BITBUCKET_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), bitbucketProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := bitbucketProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*bitbucket.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "bitbucket.org/site/oauth2/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("BITBUCKET_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=user")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := bitbucketProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://bitbucket.org/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*bitbucket.Session)
	a.Equal(session.AuthURL, "http://bitbucket.org/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func bitbucketProvider() *bitbucket.Provider {
	return bitbucket.New(os.Getenv("BITBUCKET_KEY"), os.Getenv("BITBUCKET_SECRET"), "/foo", "user")
}
