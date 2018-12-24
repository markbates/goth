package typetalk_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/typetalk"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("TYPETALK_KEY"))
	a.Equal(p.Secret, os.Getenv("SLACK_SECRET"))
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
	s := session.(*typetalk.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "typetalk.com/oauth2/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://slack.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*typetalk.Session)
	a.Equal(s.AuthURL, "https://slack.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *typetalk.Provider {
	return typetalk.New(os.Getenv("TYPETALK_KEY"), os.Getenv("TYPETALK_SECRET"), "/foo")
}
