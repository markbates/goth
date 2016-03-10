package amazon_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/amazon"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("AMAZON_KEY"))
	a.Equal(p.Secret, os.Getenv("AMAZON_SECRET"))
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
	s := session.(*amazon.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "www.amazon.com/ap/oa")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://www.amazon.com/ap/oa","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*amazon.Session)
	a.Equal(s.AuthURL, "https://www.amazon.com/ap/oa")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *amazon.Provider {
	return amazon.New(os.Getenv("AMAZON_KEY"), os.Getenv("AMAZON_SECRET"), "/foo")
}
