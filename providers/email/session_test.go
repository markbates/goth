package email_test

import (
	"testing"

	"github.com/Avyukth/goth"
	"github.com/Avyukth/goth/providers/email"
	"github.com/stretchr/testify/assert"
)

func Test_Implements_Session(t *testing.T) {
    t.Parallel()
    a := assert.New(t)
    s := &email.Session{}

    a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
    t.Parallel()
    a := assert.New(t)
    s := &email.Session{}

    _, err := s.GetAuthURL()
    a.Error(err)
    a.Contains(err.Error(), "an AuthURL has not been set")

    s.AuthURL = "/foo"
    url, err := s.GetAuthURL()
    a.NoError(err)
    a.Equal("/foo", url)
}

func Test_Authorize(t *testing.T) {
    t.Parallel()
    a := assert.New(t)
    s := &email.Session{}

    p := provider()
    
    // Create a map[string]string
    paramsMap := map[string]string{"email": "test@example.com", "token": "valid_token"}
    
    // Wrap it in a struct that satisfies goth.Params
    params := &TestParams{paramsMap}
    
    email, err := s.Authorize(p, params)
    a.NoError(err)
    a.Equal("test@example.com", email)
    a.Equal("test@example.com", s.Email)
}

func Test_Marshal(t *testing.T) {
    t.Parallel()
    a := assert.New(t)
    s := &email.Session{AuthURL: "/foo", Email: "test@example.com"}

    data := s.Marshal()
    a.Equal(`{"AuthURL":"/foo","Email":"test@example.com"}`, data)
}

func Test_String(t *testing.T) {
    t.Parallel()
    a := assert.New(t)
    s := &email.Session{AuthURL: "/foo", Email: "test@example.com"}

    a.Equal(s.String(), s.Marshal())
}

type TestParams struct {
    m map[string]string
}

func (p *TestParams) Get(key string) string {
    return p.m[key]
}
