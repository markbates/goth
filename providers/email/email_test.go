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

    a.Equal(p.CallbackURL, "/foo")
    a.Equal(p.SMTPServer, os.Getenv("SMTP_SERVER"))
    a.Equal(p.SMTPPort, os.Getenv("SMTP_PORT"))
    a.Equal(p.SMTPUsername, os.Getenv("SMTP_USERNAME"))
    a.Equal(p.SMTPPassword, os.Getenv("SMTP_PASSWORD"))
    a.Equal(p.FromEmail, os.Getenv("FROM_EMAIL"))
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
}

func Test_SendVerificationEmail(t *testing.T) {
    t.Parallel()
    a := assert.New(t)
    p := provider()
    testEmail := "test@example.com"
    err := p.SendVerificationEmail(testEmail)
    a.NoError(err)
}

func Test_FetchUser(t *testing.T) {
    t.Parallel()
    a := assert.New(t)
    p := provider()
    session := &email.Session{Email: "test@example.com"}
    user, err := p.FetchUser(session)
    a.NoError(err)
    a.Equal(user.Email, "test@example.com")
    a.Equal(user.Provider, "email")
}

func provider() *email.Provider {
    return email.New(
        "/foo",
        os.Getenv("SMTP_SERVER"),
        os.Getenv("SMTP_PORT"),
        os.Getenv("SMTP_USERNAME"),
        os.Getenv("SMTP_PASSWORD"),
        os.Getenv("FROM_EMAIL"),
    )
}
