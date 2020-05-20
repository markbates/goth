package atlassian_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/atlassian"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("JIRA_KEY"))
	a.Equal(p.Secret, os.Getenv("JIRA_SECRET"))
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
	s := session.(*atlassian.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://auth.atlassian.com/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("JIRA_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=read%3Ame")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://auth.atlassian.com/auth_url","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*atlassian.Session)
	a.Equal(s.AuthURL, "https://auth.atlassian.com/auth_url")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *atlassian.Provider {
	return atlassian.New(os.Getenv("JIRA_KEY"), os.Getenv("JIRA_SECRET"), "/foo")
}
