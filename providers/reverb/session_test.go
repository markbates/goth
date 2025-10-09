package reverb_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/reverb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &reverb.Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &reverb.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal("/foo", url)
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &reverb.Session{}

	a.Equal(`{"AuthURL":"","AccessToken":"","RefreshToken":"","ExpiresAt":"0001-01-01T00:00:00Z"}`, s.Marshal())
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &reverb.Session{}

	a.Equal(s.Marshal(), s.String())
}

func Test_Authorize(t *testing.T) {
	t.Parallel()

	t.Run("successful exchange", func(t *testing.T) {
		p := staticProvider()
		p.HTTPClient = &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				require.Equal(t, http.MethodPost, req.Method)
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				require.NoError(t, req.Body.Close())
				require.Contains(t, string(body), "code=auth-code")
				require.Contains(t, string(body), "grant_type=authorization_code")
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
		require.NoError(t, err)

		assert.Equal(t, "token", token)
		assert.Equal(t, "token", session.AccessToken)
		assert.Equal(t, "refresh", session.RefreshToken)
		assert.False(t, session.ExpiresAt.IsZero())
	})

	t.Run("invalid token response", func(t *testing.T) {
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
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token received")
	})

	t.Run("exchange error", func(t *testing.T) {
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
		assert.Error(t, err)
	})
}
