package bitly_test

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/markbates/goth/providers/bitly"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := bitlyProvider()
	a.Equal(p.ClientKey, "bitly_client_id")
	a.Equal(p.Secret, "bitly_client_secret")
	a.Equal(p.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := bitlyProvider()
	s, err := p.BeginAuth("state")
	s1 := s.(*bitly.Session)

	a.NoError(err)
	a.Contains(s1.AuthURL, "https://bitly.com/oauth/authorize")
	a.Contains(s1.AuthURL, fmt.Sprintf("client_id=%s", p.ClientKey))
	a.Contains(s1.AuthURL, "state=state")
	a.Contains(s1.AuthURL, fmt.Sprintf("redirect_uri=%s", url.QueryEscape(p.CallbackURL)))
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := bitlyProvider()
	s, err := p.UnmarshalSession(`{"AuthURL":"https://bitly.com/oauth/authorize","AccessToken":"access_token"}`)
	s1 := s.(*bitly.Session)

	a.NoError(err)
	a.Equal(s1.AuthURL, "https://bitly.com/oauth/authorize")
	a.Equal(s1.AccessToken, "access_token")
}

func bitlyProvider() *bitly.Provider {
	return bitly.New("bitly_client_id", "bitly_client_secret", "/foo")
}
