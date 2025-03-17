package jira_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/jira"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := jiraProvider()
	a.Equal(provider.ClientKey, os.Getenv("JIRA_KEY"))
	a.Equal(provider.Secret, os.Getenv("JIRA_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), jiraProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := jiraProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*jira.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "auth.atlassian.com/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("JIRA_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=user")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := jiraProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://auth.atlassian.com/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*jira.Session)
	a.Equal(session.AuthURL, "https://auth.atlassian.com/authorize")
	a.Equal(session.AccessToken, "1234567890")
}

func jiraProvider() *jira.Provider {
	return jira.New(os.Getenv("JIRA_KEY"), os.Getenv("JIRA_SECRET"), "/foo", "user")
}
