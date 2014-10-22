package twitter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/pat"
	"github.com/markbates/goth"
	"github.com/mrjones/oauth"
	"github.com/stretchr/testify/assert"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := twitterProvider()
	a.Equal(provider.ClientKey, os.Getenv("TWITTER_KEY"))
	a.Equal(provider.Secret, os.Getenv("TWITTER_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), twitterProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	mockTwitter(func(ts *httptest.Server) {
		provider := twitterProvider()
		session, err := provider.BeginAuth()
		s := session.(*Session)
		a.NoError(err)
		a.Contains(s.AuthURL, "oauth_token=TOKEN")
		a.Equal("TOKEN", s.RequestToken.Token)
		a.Equal("SECRET", s.RequestToken.Secret)
	})
}

func Test_FetchUser(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	mockTwitter(func(ts *httptest.Server) {
		provider := twitterProvider()
		session := Session{AccessToken: &oauth.AccessToken{Token: "TOKEN", Secret: "SECRET"}}

		user, err := provider.FetchUser(&session)
		a.NoError(err)

		a.Equal("Homer", user.Name)
		a.Equal("duffman", user.NickName)
		a.Equal("Duff rules!!", user.Description)
		a.Equal("http://example.com/image.jpg", user.AvatarURL)
		a.Equal("1234", user.UserID)
		a.Equal("Springfield", user.Location)
		a.Equal("TOKEN", user.AccessToken)
		a.Empty(user.Email)
	})
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := twitterProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://twitter.com/auth_url","AccessToken":{"Token":"1234567890","Secret":"secret!!","AdditionalData":{}},"RequestToken":{"Token":"0987654321","Secret":"!!secret"}}`)
	a.NoError(err)
	session := s.(*Session)
	a.Equal(session.AuthURL, "http://twitter.com/auth_url")
	a.Equal(session.AccessToken.Token, "1234567890")
	a.Equal(session.AccessToken.Secret, "secret!!")
	a.Equal(session.RequestToken.Token, "0987654321")
	a.Equal(session.RequestToken.Secret, "!!secret")
}

func twitterProvider() *Provider {
	return New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "/foo")
}

func mockTwitter(f func(*httptest.Server)) {
	p := pat.New()
	p.Get("/oauth/request_token", func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprint(res, "oauth_token=TOKEN&oauth_token_secret=SECRET")
	})
	p.Get("/1.1/account/verify_credentials.json", func(res http.ResponseWriter, req *http.Request) {
		data := map[string]string{
			"name":              "Homer",
			"screen_name":       "duffman",
			"description":       "Duff rules!!",
			"profile_image_url": "http://example.com/image.jpg",
			"id_str":            "1234",
			"location":          "Springfield",
		}
		json.NewEncoder(res).Encode(&data)
	})
	ts := httptest.NewServer(p)
	defer ts.Close()

	originalRequestURL := RequestURL
	originalEndpointProfile := EndpointProfile

	RequestURL = ts.URL + "/oauth/request_token"
	EndpointProfile = ts.URL + "/1.1/account/verify_credentials.json"

	f(ts)

	RequestURL = originalRequestURL
	EndpointProfile = originalEndpointProfile
}
