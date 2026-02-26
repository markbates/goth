package twitterv2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/pat"
	"github.com/markbates/goth"
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

	provider := twitterProvider()
	session, err := provider.BeginAuth("state")
	s := session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "twitter.com/i/oauth2/authorize")
	a.Contains(s.AuthURL, "code_challenge=")
	a.Contains(s.AuthURL, "code_challenge_method=S256")
	a.NotEmpty(s.CodeVerifier)

	provider = twitterProviderAuthenticate()
	session, err = provider.BeginAuth("state")
	s = session.(*Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "twitter.com/i/oauth2/authorize")
	a.Contains(s.AuthURL, "code_challenge=")
	a.Contains(s.AuthURL, "code_challenge_method=S256")
	a.NotEmpty(s.CodeVerifier)
}

func Test_FetchUser(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := twitterProvider()
	session := Session{AccessToken: "TOKEN", RefreshToken: "REFRESH", ExpiresAt: time.Now()}

	user, err := provider.FetchUser(&session)
	a.NoError(err)

	a.Equal("Homer", user.Name)
	a.Equal("duffman", user.NickName)
	a.Equal("Duff rules!!", user.Description)
	a.Equal("http://example.com/image.jpg", user.AvatarURL)
	a.Equal("1234", user.UserID)
	a.Equal("Springfield", user.Location)
	a.Equal("TOKEN", user.AccessToken)
	a.Equal("REFRESH", user.RefreshToken)
	a.Equal("", user.Email) // email is not strictly mapped right now natively
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := twitterProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://com/auth_url","AccessToken":"1234567890","RefreshToken":"refresh","CodeVerifier":"verifier"}`)
	a.NoError(err)
	session := s.(*Session)
	a.Equal(session.AuthURL, "http://com/auth_url")
	a.Equal(session.AccessToken, "1234567890")
	a.Equal(session.RefreshToken, "refresh")
	a.Equal(session.CodeVerifier, "verifier")
}

func twitterProvider() *Provider {
	return New(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "/foo")
}

func twitterProviderAuthenticate() *Provider {
	return NewAuthenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), "/foo")
}

func init() {
	p := pat.New()
	p.Get("/2/users/me", func(res http.ResponseWriter, req *http.Request) {
		data := map[string]interface{}{
			"data": map[string]string{
				"name":              "Homer",
				"username":          "duffman",
				"description":       "Duff rules!!",
				"profile_image_url": "http://example.com/image.jpg",
				"id":                "1234",
				"location":          "Springfield",
				"email":             "duffman@springfield.com",
			},
		}
		json.NewEncoder(res).Encode(&data)
	})
	ts := httptest.NewServer(p)

	endpointProfile = ts.URL + "/2/users/me"
}
