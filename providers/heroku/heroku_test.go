package heroku_test

import (
	"os"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/heroku"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("HEROKU_KEY"))
	a.Equal(p.Secret, os.Getenv("HEROKU_SECRET"))
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
	s := session.(*heroku.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "id.heroku.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://id.heroku.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*heroku.Session)
	a.Equal(s.AuthURL, "https://id.heroku.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *heroku.Provider {
	return heroku.New(os.Getenv("HEROKU_KEY"), os.Getenv("HEROKU_SECRET"), "/foo")
}
