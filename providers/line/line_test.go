package line_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/line"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("LINE_CLIENT_ID"))
	a.Equal(p.Secret, os.Getenv("LINE_CLIENT_SECRET"))
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
	s := session.(*line.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://access.line.me/oauth2/v2.1/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://access.line.me/oauth2/v2.1/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*line.Session)
	a.Equal(s.AuthURL, "https://access.line.me/oauth2/v2.1/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func Test_SetBotPrompt(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	p.SetBotPrompt("normal")
	session, err := p.BeginAuth("test_state")
	s := session.(*line.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "bot_prompt=normal")
}

func provider() *line.Provider {
	return line.New(os.Getenv("LINE_CLIENT_ID"), os.Getenv("LINE_CLIENT_SECRET"), "/foo")
}
