package intercom_test

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/pat"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/intercom"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type fetchUserPayload struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Link          string `json:"link"`
	EmailVerified bool   `json:"email_verified"`
	Avatar        struct {
		URL string `json:"image_url"`
	} `json:"avatar"`
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := intercomProvider()
	a.Equal(provider.ClientKey, os.Getenv("INTERCOM_KEY"))
	a.Equal(provider.Secret, os.Getenv("INTERCOM_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	a.Implements((*goth.Provider)(nil), intercomProvider())
}
func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	provider := intercomProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*intercom.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://app.intercom.io/oauth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("INTERCOM_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := intercomProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://app.intercom.io/oauth","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*intercom.Session)
	a.Equal(session.AuthURL, "https://app.intercom.io/oauth")
	a.Equal(session.AccessToken, "1234567890")
}

func intercomProvider() *intercom.Provider {
	return intercom.New(os.Getenv("INTERCOM_KEY"), os.Getenv("INTERCOM_SECRET"), "/foo", "basic")
}

func Test_FetchUser(t *testing.T) {
	a := assert.New(t)

	u := fetchUserPayload{}
	u.ID = "1"
	u.Email = "wash@serenity.now"
	u.Name = "Hoban Washburne"
	u.EmailVerified = true
	u.Avatar.URL = "http://avatarURL"

	mockIntercomFetchUser(&u, func(ts *httptest.Server) {
		provider := intercomProvider()
		session := &intercom.Session{AccessToken: "token"}

		user, err := provider.FetchUser(session)
		a.NoError(err)

		a.Equal("1", user.UserID)
		a.Equal("wash@serenity.now", user.Email)
		a.Equal("Hoban Washburne", user.Name)
		a.Equal("Hoban", user.FirstName)
		a.Equal("Washburne", user.LastName)
		a.Equal("http://avatarURL", user.AvatarURL)
		a.Equal(true, user.RawData["email_verified"])
		a.Equal("token", user.AccessToken)
	})
}

func Test_FetchUnverifiedUser(t *testing.T) {
	a := assert.New(t)

	u := fetchUserPayload{}
	u.ID = "1"
	u.Email = "wash@serenity.now"
	u.Name = "Hoban Washburne"
	u.EmailVerified = false
	u.Avatar.URL = "http://avatarURL"

	mockIntercomFetchUser(&u, func(ts *httptest.Server) {
		provider := intercomProvider()
		session := &intercom.Session{AccessToken: "token"}

		user, err := provider.FetchUser(session)
		a.NoError(err)

		a.Equal("1", user.UserID)
		a.Equal("wash@serenity.now", user.Email)
		a.Equal("Hoban Washburne", user.Name)
		a.Equal("Hoban", user.FirstName)
		a.Equal("Washburne", user.LastName)
		a.Equal("http://avatarURL", user.AvatarURL)
		a.Equal(false, user.RawData["email_verified"])
		a.Equal("token", user.AccessToken)
	})
}

func mockIntercomFetchUser(fetchUserPayload *fetchUserPayload, f func(*httptest.Server)) {
	p := pat.New()
	p.Get("/me", func(res http.ResponseWriter, req *http.Request) {
		json.NewEncoder(res).Encode(fetchUserPayload)
	})
	ts := httptest.NewServer(p)
	defer ts.Close()

	originalUserURL := intercom.UserURL

	intercom.UserURL = ts.URL + "/me"

	f(ts)

	intercom.UserURL = originalUserURL
}
