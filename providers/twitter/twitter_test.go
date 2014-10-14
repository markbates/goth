package twitter_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/twitter"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := twitterProvider()
	a.Equal(provider.ClientKey, os.Getenv("TWITTER_KEY"))
	a.Equal(provider.Secret, os.Getenv("TWITTER_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), twitterProvider())
}

// TODO: Implement a better solution
// func Test_BeginAuth(t *testing.T) {
// 	t.Parallel()
// 	a := assert.New(t)
//
// 	provider := twitterProvider()
// 	session, err := provider.BeginAuth()
// 	s := session.(*twitter.Session)
// 	a.NoError(err)
// 	a.Contains(s.AuthURL, "https://api.twitter.com/oauth/authorize?oauth_token=")
// 	a.NotEmpty(s.RequestToken.Secret)
// 	a.NotEmpty(s.RequestToken.Token)
// }

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := twitterProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://twitter.com/auth_url","AccessToken":{"Token":"1234567890","Secret":"secret!!","AdditionalData":{}},"RequestToken":{"Token":"0987654321","Secret":"!!secret"}}`)
	a.NoError(err)
	session := s.(*twitter.Session)
	a.Equal(session.AuthURL, "http://twitter.com/auth_url")
	a.Equal(session.AccessToken.Token, "1234567890")
	a.Equal(session.AccessToken.Secret, "secret!!")
	a.Equal(session.RequestToken.Token, "0987654321")
	a.Equal(session.RequestToken.Secret, "!!secret")
}

func twitterProvider() *twitter.Provider {
	return twitter.New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "/foo")
}
