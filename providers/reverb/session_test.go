package reverb_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/reverb"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	s := &reverb.Session{}

	r.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	s := &reverb.Session{}

	_, err := s.GetAuthURL()
	r.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	r.Equal("/foo", url)
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	s := &reverb.Session{}

	r.Equal(`{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z"}`, s.Marshal())
}

func Test_String(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	s := &reverb.Session{}

	r.Equal(s.Marshal(), s.String())
}

func Test_Authorize(t *testing.T) {
	t.Parallel()

	t.Run("successful exchange", func(t *testing.T) {
		r := require.New(t)
		p := staticProvider()
		p.HTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				r.Equal(http.MethodPost, req.Method)
				body, err := io.ReadAll(req.Body)
				r.NoError(err)
				r.NoError(req.Body.Close())
				r.Contains(string(body), "code=auth-code")
				r.Contains(string(body), "grant_type=authorization_code")
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(
						`{"access_token":"token","refresh_token":"refresh","expires_in":3600,"token_type":"bearer"}`,
					)),
					Header: make(http.Header),
				}, nil
			}),
		}

		session := &reverb.Session{}
		value := url.Values{"code": {"auth-code"}}
		token, err := session.Authorize(p, value)
		r.NoError(err)

		r.Equal("token", token)
		r.Equal("token", session.AccessToken)
		r.Equal("refresh", session.RefreshToken)
		r.False(session.ExpiresAt.IsZero())
	})

	t.Run("invalid token response", func(t *testing.T) {
		r := require.New(t)
		p := staticProvider()
		p.HTTPClient = &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: io.NopCloser(strings.NewReader(
						`{"access_token":"expired","refresh_token":"refresh","expires_in":-3600,"token_type":"bearer"}`,
					)),
					Header: make(http.Header),
				}, nil
			}),
		}

		session := &reverb.Session{}
		_, err := session.Authorize(p, url.Values{"code": {"auth-code"}})
		r.Error(err)
		r.Contains(err.Error(), "invalid token received")
	})

	t.Run("nil provider", func(t *testing.T) {
		r := require.New(t)
		session := &reverb.Session{}
		_, err := session.Authorize(nil, url.Values{"code": {"auth-code"}})
		r.Error(err)
	})

	t.Run("nil params", func(t *testing.T) {
		r := require.New(t)
		session := &reverb.Session{}
		_, err := session.Authorize(staticProvider(), nil)
		r.Error(err)
	})

	t.Run("nil session receiver", func(t *testing.T) {
		r := require.New(t)
		var session *reverb.Session
		_, err := session.Authorize(staticProvider(), url.Values{"code": {"auth-code"}})
		r.Error(err)
	})

	t.Run("missing authorization code", func(t *testing.T) {
		r := require.New(t)
		session := &reverb.Session{}
		_, err := session.Authorize(staticProvider(), url.Values{})
		r.Error(err)
	})

	t.Run("provider missing config", func(t *testing.T) {
		r := require.New(t)
		session := &reverb.Session{}
		provider := &reverb.Provider{}
		_, err := session.Authorize(provider, url.Values{"code": {"auth-code"}})
		r.Error(err)
	})

	t.Run("invalid provider type", func(t *testing.T) {
		r := require.New(t)
		session := &reverb.Session{}
		_, err := session.Authorize(fakeProvider{}, url.Values{"code": {"auth-code"}})
		r.Error(err)
	})

	t.Run("exchange error", func(t *testing.T) {
		r := require.New(t)
		p := staticProvider()
		p.HTTPClient = &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`)),
					Header:     make(http.Header),
				}, nil
			}),
		}

		session := &reverb.Session{}
		_, err := session.Authorize(p, url.Values{"code": {"auth-code"}})
		r.Error(err)
	})
}

type fakeProvider struct{}

func (fakeProvider) Name() string { return "fake" }

func (fakeProvider) SetName(string) {}

func (fakeProvider) BeginAuth(string) (goth.Session, error) { return nil, nil }

func (fakeProvider) UnmarshalSession(string) (goth.Session, error) { return nil, nil }

func (fakeProvider) FetchUser(goth.Session) (goth.User, error) { return goth.User{}, nil }

func (fakeProvider) Debug(bool) {}

func (fakeProvider) RefreshToken(string) (*oauth2.Token, error) { return nil, nil }

func (fakeProvider) RefreshTokenAvailable() bool { return false }
