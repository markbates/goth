package xero

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

	provider := xeroProvider()
	a.Equal(provider.ClientKey, os.Getenv("XERO_KEY"))
	a.Equal(provider.Secret, os.Getenv("XERO_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), xeroProvider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	mockXero(func(ts *httptest.Server) {
		provider := xeroProvider()
		session, err := provider.BeginAuth("state")
		if err != nil {
			a.Error(err, nil)
		}
		s := session.(*Session)
		a.NoError(err)
		a.Contains(s.AuthURL, "Authorize")
		a.Equal("TOKEN", s.RequestToken.Token)
		a.Equal("SECRET", s.RequestToken.Secret)
	})
}

func Test_FetchUser(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	mockXero(func(ts *httptest.Server) {
		provider := xeroProvider()
		session := Session{AccessToken: &oauth.AccessToken{Token: "TOKEN", Secret: "SECRET"}}

		user, err := provider.FetchUser(&session)
		if err != nil {
			a.Error(err, nil)
		}

		a.NoError(err)

		a.Equal("Vanderlay Industries", user.Name)
		a.Equal("Vanderlay Industries", user.NickName)
		a.Equal("COMPANY", user.Description)
		a.Equal("111-11", user.UserID)
		a.Equal("NZ", user.Location)
		a.Empty(user.Email)
	})
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := xeroProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"http://com/auth_url","AccessToken":{"Token":"1234567890","Secret":"secret!!","AdditionalData":{}},"RequestToken":{"Token":"0987654321","Secret":"!!secret"}}`)
	a.NoError(err)
	session := s.(*Session)
	a.Equal(session.AuthURL, "http://com/auth_url")
	a.Equal(session.AccessToken.Token, "1234567890")
	a.Equal(session.AccessToken.Secret, "secret!!")
	a.Equal(session.RequestToken.Token, "0987654321")
	a.Equal(session.RequestToken.Secret, "!!secret")
}

func xeroProvider() *Provider {
	return New(os.Getenv("XERO_KEY"), os.Getenv("XERO_SECRET"), "/foo")
}

func mockXero(f func(*httptest.Server)) {
	p := pat.New()
	p.Get("/oauth/RequestToken", func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprint(res, "oauth_token=TOKEN&oauth_token_secret=SECRET")
	})
	p.Get("/oauth/Authorize", func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprint(res, "DO NOT USE THIS ENDPOINT")
	})
	p.Get("/oauth/AccessToken", func(res http.ResponseWriter, req *http.Request) {
		fmt.Fprint(res, "oauth_token=TOKEN&oauth_token_secret=SECRET")
	})
	p.Get("/api.xro/2.0/Organisation", func(res http.ResponseWriter, req *http.Request) {
		apiResponse := APIResponse{
			Organisations: []Organisation{
				{"Vanderlay Industries", "Vanderlay Industries", "COMPANY", "NZ", "111-11"},
			},
		}

		js, err := json.Marshal(apiResponse)
		if err != nil {
			fmt.Fprint(res, "Json did not Marshal")
		}

		res.Write(js)
	})

	ts := httptest.NewServer(p)
	defer ts.Close()

	originalRequestURL := requestURL
	originalEndpointProfile := endpointProfile
	originalAuthorizeURL := authorizeURL
	originalAccessTokenURL := tokenURL

	requestURL = ts.URL + "/oauth/RequestToken"
	endpointProfile = ts.URL + "/api.xro/2.0/"
	authorizeURL = ts.URL + "/oauth/Authorize"
	tokenURL = ts.URL + "/oauth/AccessToken"

	f(ts)

	requestURL = originalRequestURL
	endpointProfile = originalEndpointProfile
	authorizeURL = originalAuthorizeURL
	tokenURL = originalAccessTokenURL
}
