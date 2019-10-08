package slack_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/slack"
	"github.com/stretchr/testify/assert"
)

var (
	testAuthTestResponseData = map[string]interface{}{
		"user":    "testuser",
		"user_id": "user1234",
	}

	testUserInfoResponseData = map[string]interface{}{
		"user": map[string]interface{}{
			"id":   testAuthTestResponseData["user_id"],
			"name": testAuthTestResponseData["user"],
			"profile": map[string]interface{}{
				"real_name":  "Test User",
				"first_name": "Test",
				"last_name":  "User",
				"image_32":   "http://example.org/avatar.png",
				"email":      "test@example.org",
			},
		},
	}
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(p.ClientKey, os.Getenv("SLACK_KEY"))
	a.Equal(p.Secret, os.Getenv("SLACK_SECRET"))
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
	s := session.(*slack.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "slack.com/oauth/authorize")
}

func Test_FetchUser(t *testing.T) {
	t.Parallel()

	for _, testData := range []struct {
		name         string
		provider     *slack.Provider
		session      goth.Session
		handler      http.Handler
		expectedUser goth.User
		expectErr    bool
	}{
		{
			name:     "FetchesFullProfile",
			provider: provider(),
			session:  &slack.Session{AccessToken: "TOKEN"},
			handler: http.HandlerFunc(
				func(res http.ResponseWriter, req *http.Request) {
					switch req.URL.Path {
					case "/api/auth.test":
						res.WriteHeader(http.StatusOK)
						json.NewEncoder(res).Encode(testAuthTestResponseData)
					case "/api/users.info":
						res.WriteHeader(http.StatusOK)
						json.NewEncoder(res).Encode(testUserInfoResponseData)
					default:
						res.WriteHeader(http.StatusNotFound)
					}
				},
			),
			expectedUser: goth.User{
				UserID:      "user1234",
				NickName:    "testuser",
				Name:        "Test User",
				FirstName:   "Test",
				LastName:    "User",
				AvatarURL:   "http://example.org/avatar.png",
				Email:       "test@example.org",
				AccessToken: "TOKEN",
			},
			expectErr: false,
		},
		{
			name:      "FailsWithNoAccessToken",
			provider:  provider(),
			session:   &slack.Session{AccessToken: ""},
			handler:   nil,
			expectErr: true,
		},
		{
			name:     "FailsWithBadBasicInfoResponse",
			provider: provider(),
			session:  &slack.Session{AccessToken: "TOKEN"},
			handler: http.HandlerFunc(
				func(res http.ResponseWriter, req *http.Request) {
					switch req.URL.Path {
					case "/api/auth.test":
						res.WriteHeader(http.StatusNotFound)
					}
				},
			),
			expectedUser: goth.User{
				AccessToken: "TOKEN",
			},
			expectErr: true,
		},
	} {
		t.Run(testData.name, func(t *testing.T) {
			a := assert.New(t)

			withMockServer(testData.provider, testData.handler, func(p *slack.Provider) {
				user, err := p.FetchUser(testData.session)
				a.NotZero(user)

				if testData.expectErr {
					a.Error(err)
				} else {
					a.NoError(err)
				}

				a.Equal(testData.expectedUser.UserID, user.UserID)
				a.Equal(testData.expectedUser.NickName, user.NickName)
				a.Equal(testData.expectedUser.Name, user.Name)
				a.Equal(testData.expectedUser.FirstName, user.FirstName)
				a.Equal(testData.expectedUser.LastName, user.LastName)
				a.Equal(testData.expectedUser.AvatarURL, user.AvatarURL)
				a.Equal(testData.expectedUser.Email, user.Email)
				a.Equal(testData.expectedUser.AccessToken, user.AccessToken)
			})
		})
	}
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://slack.com/oauth/authorize","AccessToken":"1234567890"}`)
	a.NoError(err)

	s := session.(*slack.Session)
	a.Equal(s.AuthURL, "https://slack.com/oauth/authorize")
	a.Equal(s.AccessToken, "1234567890")
}

func provider() *slack.Provider {
	return slack.New(os.Getenv("SLACK_KEY"), os.Getenv("SLACK_SECRET"), "/foo")
}

func withMockServer(p *slack.Provider, handler http.Handler, fn func(p *slack.Provider)) {
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return net.Dial(network, server.Listener.Addr().String())
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	p.HTTPClient = httpClient

	fn(p)
}
