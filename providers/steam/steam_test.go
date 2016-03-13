package steam_test

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/steam"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.APIKey, os.Getenv("STEAM_KEY"))
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
	s := session.(*steam.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "steamcommunity.com/openid/login")
	a.Contains(s.AuthURL, "foo")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_setup&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.realm=%3A%2F%2F&openid.return_to=%2Ffoo","SteamID":"1234567890","CallbackURL":"http://localhost:3030/","ResponseNonce":"2016-03-13T16:56:30ZJ8tlKVquwHi9ZSPV4ElU5PY2dmI="}`)
	a.NoError(err)

	s := session.(*steam.Session)
	a.Equal(s.AuthURL, "https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_setup&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.realm=%3A%2F%2F&openid.return_to=%2Ffoo")
	a.Equal(s.CallbackURL, "http://localhost:3030/")
	a.Equal(s.SteamID, "1234567890")
	a.Equal(s.ResponseNonce, "2016-03-13T16:56:30ZJ8tlKVquwHi9ZSPV4ElU5PY2dmI=")
}

func provider() *steam.Provider {
	return steam.New(os.Getenv("STEAM_KEY"), "/foo")
}
