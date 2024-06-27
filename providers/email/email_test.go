package email_test

import (
	"os"
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/email"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal("/foo", p.CallbackURL)
	a.Equal("localhost", p.config.Server.Host)
	a.Equal(25, p.config.Server.Port)
	a.Equal("", p.config.Server.User)
	a.Equal("", p.config.Server.Pass)
	a.Equal("Auth.js <no-reply@authjs.dev>", p.config.From)
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
	s := session.(*email.Session)
	a.NoError(err)
	a.Empty(s.Email) // Email should be empty at this point
	a.Equal("/foo", s.AuthURL)
}

func Test_FetchUser(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	session := &email.Session{Email: "test@example.com"}
	user, err := p.FetchUser(session)
	a.NoError(err)
	a.Equal("test@example.com", user.Email)
	a.Equal("email", user.Provider)
}

func Test_SendVerificationRequest(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()
	testEmail := "test@example.com"
	err := p.SendVerificationRequest(testEmail, "http://localhost:3000/callback")
	a.NoError(err)
}

func provider() *email.Provider {
	return email.New("clientKey", "secret", "/foo", &email.Config{
		Server: email.SMTPServer{
			Host: "localhost",
			Port: 25,
			User: "",
			Pass: "",
		},
		From:   "pathshala.dev <no-reply@pathshala.dev>",
		MaxAge: 24 * 60 * 60,
	})
}
