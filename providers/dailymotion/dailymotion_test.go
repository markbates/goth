package dailymotion_test

import (
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/dailymotion"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := dailymotionProvider()
	a.Equal(provider.ClientKey, os.Getenv("DAILYMOTION_KEY"))
	a.Equal(provider.Secret, os.Getenv("DAILYMOTION_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), dailymotionProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := dailymotionProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*dailymotion.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://www.dailymotion.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := dailymotionProvider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://www.dailymotion.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*dailymotion.Session)
	a.Equal(s.AuthURL, "https://www.dailymotion.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func dailymotionProvider() *dailymotion.Provider {
	return dailymotion.New(os.Getenv("DAILYMOTION_KEY"), os.Getenv("DAILYMOTION_SECRET"), "/foo", "email")
}
