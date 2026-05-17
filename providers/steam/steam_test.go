package steam_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/steam"
	"github.com/stretchr/testify/assert"
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

func Test_FetchUser(t *testing.T) {
	// Regression test for the gap that left goth.User.RawData empty for the
	// steam provider (originally raised in PR #518). Beyond the six typed
	// fields the provider already mapped, RawData should expose the full
	// Steam player payload so callers can read fields without a slot on
	// goth.User -- communityvisibilitystate, primaryclanid, timecreated, etc.
	apiUserSummaryPath := "/ISteamUser/GetPlayerSummaries/v0002/?key=%s&steamids=%s"

	t.Parallel()
	a := assert.New(t)
	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://steamcommunity.com/openid/login?openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_setup&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.realm=%3A%2F%2F&openid.return_to=%2Ffoo","SteamID":"1234567890","CallbackURL":"http://localhost:3030/","ResponseNonce":"2016-03-13T16:56:30ZJ8tlKVquwHi9ZSPV4ElU5PY2dmI="}`)
	a.NoError(err)

	expectedPath := fmt.Sprintf(apiUserSummaryPath, p.APIKey, "1234567890")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.Equal("application/json", r.Header.Get("Accept"))
		a.Equal(http.MethodGet, r.Method)
		a.Equal(expectedPath, r.URL.RequestURI())
		_, _ = w.Write([]byte(testUserSummaryBody))
	}))
	defer ts.Close()

	p.HTTPClient = ts.Client()
	p.HTTPClient.Transport = &httpTestTransport{server: ts}

	user, err := p.FetchUser(session)
	a.NoError(err)

	// Typed fields land where they always did.
	a.Equal("76561197960435530", user.UserID)
	a.Equal("Robin", user.NickName)
	a.Equal("Robin Walker", user.Name)
	a.Equal("https://avatars.steamstatic.com/81b5478529dce13bf24b55ac42c1af7058aaf7a9_full.jpg", user.AvatarURL)
	a.Equal("No email is provided by the Steam API", user.Email)
	a.Equal("No description is provided by the Steam API", user.Description)
	a.Equal("WA, US", user.Location)

	// RawData mirrors the six typed fields ...
	a.Equal("76561197960435530", user.RawData["steamid"])
	a.Equal("Robin", user.RawData["personaname"])
	a.Equal("Robin Walker", user.RawData["realname"])
	a.Equal("https://avatars.steamstatic.com/81b5478529dce13bf24b55ac42c1af7058aaf7a9_full.jpg", user.RawData["avatarfull"])
	a.Equal("US", user.RawData["loccountrycode"])
	a.Equal("WA", user.RawData["locstatecode"])
	// ... and also the fields without a slot on goth.User. These are the
	// ones consumers had no other way to reach before; locking them in
	// prevents a future refactor from silently shrinking the payload.
	a.EqualValues(3, user.RawData["communityvisibilitystate"])
	a.EqualValues(1, user.RawData["profilestate"])
	a.EqualValues(0, user.RawData["personastate"])
	a.Equal("103582791429521408", user.RawData["primaryclanid"])
	a.EqualValues(1063407589, user.RawData["timecreated"])
	a.Equal("https://steamcommunity.com/id/robinwalker/", user.RawData["profileurl"])
}

func provider() *steam.Provider {
	return steam.New(os.Getenv("STEAM_KEY"), "/foo")
}

type httpTestTransport struct {
	server *httptest.Server
}

func (t *httpTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	uri, err := url.Parse(t.server.URL)
	if err != nil {
		return nil, err
	}

	req.URL.Scheme = uri.Scheme
	req.URL.Host = uri.Host

	return http.DefaultTransport.RoundTrip(req)
}

// Reference: https://developer.valvesoftware.com/wiki/Steam_Web_API
// Extended beyond the six fields the typed struct extracts so the test also
// guards the RawData fallthrough for fields that have no slot on goth.User.
var testUserSummaryBody = `{
	"response": {
		"players": [
			{
				"steamid": "76561197960435530",
				"communityvisibilitystate": 3,
				"profilestate": 1,
				"personaname": "Robin",
				"profileurl": "https://steamcommunity.com/id/robinwalker/",
				"avatar": "https://avatars.steamstatic.com/81b5478529dce13bf24b55ac42c1af7058aaf7a9.jpg",
				"avatarmedium": "https://avatars.steamstatic.com/81b5478529dce13bf24b55ac42c1af7058aaf7a9_medium.jpg",
				"avatarfull": "https://avatars.steamstatic.com/81b5478529dce13bf24b55ac42c1af7058aaf7a9_full.jpg",
				"personastate": 0,
				"primaryclanid": "103582791429521408",
				"timecreated": 1063407589,
				"realname": "Robin Walker",
				"loccountrycode": "US",
				"locstatecode": "WA"
			}
		]
	}
}`
