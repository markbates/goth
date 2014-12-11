package github_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := githubProvider()
	a.Equal(provider.ClientKey, os.Getenv("GITHUB_KEY"))
	a.Equal(provider.Secret, os.Getenv("GITHUB_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), githubProvider())
}

// TODO: Implement a better solution
// func Test_BeginAuth(t *testing.T) {
// 	t.Parallel()
// 	a := assert.New(t)
//
// 	provider := githubProvider()
// 	session, err := provider.BeginAuth()
// 	s := session.(*github.Session)
// 	a.NoError(err)
// 	a.Equal(s.AuthURL, fmt.Sprintf("https://www.github.com/dialog/oauth?client_id=%s&redirect_uri=%%2Ffoo&response_type=code&state=state", provider.ClientKey))
// }

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := githubProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://github.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*github.Session)
	a.Equal(session.AuthURL, "http://github.com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
}

func githubProvider() *github.Provider {
	return github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), "/foo")
}
