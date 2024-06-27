package gitea_test

import (
	"os"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/gitea"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("GITEA_KEY"))
	a.Equal(p.Secret, os.Getenv("GITEA_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := urlCustomisedURLProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*gitea.Session)
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
	s := session.(*gitea.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "gitea.com/login/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://gitea.com/login/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*gitea.Session)
	a.Equal(s.AuthURL, "https://gitea.com/login/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *gitea.Provider {
	return gitea.New(os.Getenv("GITEA_KEY"), os.Getenv("GITEA_SECRET"), "/foo")
}

func urlCustomisedURLProvider() *gitea.Provider {
	return gitea.NewCustomisedURL(os.Getenv("GITEA_KEY"), os.Getenv("GITEA_SECRET"), "/foo", "http://authURL", "http://tokenURL", "http://profileURL")
}
