package gitee

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
)

func newProvider() *Provider {
	return New(os.Getenv("GITEE_KEY"), os.Getenv("GITEE_SECRET"), "/foo", "user")
}

func newCustomisedProvider() *Provider {
	return NewCustomisedURL(os.Getenv("GITEE_KEY"), os.Getenv("GITEE_SECRET"), "/foo", "http://authURL", "http://tokenURL", "http://profileURL", "http://emailURL")
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := newProvider()
	a.Equal(provider.Key, os.Getenv("GITEE_KEY"))
	a.Equal(provider.Secret, os.Getenv("GITEE_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_NewCustomisedURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := newCustomisedProvider()
	sess, err := p.BeginAuth("state")
	a.NoError(err)

	authURL, err := sess.GetAuthURL()
	a.NoError(err)
	a.Contains(authURL, "http://authURL")
}

func TestImplementProvider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), newProvider())
}

func TestBeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := newProvider()
	sess, err := provider.BeginAuth("state")
	a.NoError(err)

	authURL, err := sess.GetAuthURL()
	a.NoError(err)
	a.Contains(authURL, "gitee.com/oauth/authorize")
	a.Contains(authURL, fmt.Sprintf("client_id=%s", os.Getenv("GITEE_KEY")))
	a.Contains(authURL, "state=state")
	a.Contains(authURL, "scope=user")
}

func TestSessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	provider := newProvider()
	sess, err := provider.UnmarshalSession(`{"AuthURL":"http://gitee.com/auth_url","AccessToken":"01234567890"}`)
	a.NoError(err)
	authURL, err := sess.GetAuthURL()
	a.NoError(err)

	a.Equal(authURL, "http://gitee.com/auth_url")
}

func Test_parse(t *testing.T) {
	a := assert.New(t)
	s := `
	{
		"id": 123456,
		"login": "login_name",
		"name": "name",
		"bio": "some bio",
		"email": ""
	}
	`
	r := strings.NewReader(s)
	user := &goth.User{}
	err := parseUserFromBody(r, user)
	a.NoError(err)
}
