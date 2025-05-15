package linkedin_test

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/linkedin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockParams struct {
	params map[string]string
}

func (m *MockParams) Get(key string) string {
	return m.params[key]
}

type MockedHTTPClient struct {
	mock.Mock
}

func (m *MockedHTTPClient) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Mock.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &linkedin.Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &linkedin.Session{}

	_, err := s.GetAuthURL()
	a.Error(err)

	s.AuthURL = "/foo"

	url, _ := s.GetAuthURL()
	a.Equal(url, "/foo")
}

func Test_ToJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &linkedin.Session{}

	data := s.Marshal()
	a.Equal(data, `{"AuthURL":"","AccessToken":"","ExpiresAt":"0001-01-01T00:00:00Z"}`)
}

func Test_String(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &linkedin.Session{}

	a.Equal(s.String(), s.Marshal())
}

func Test_Authorize(t *testing.T) {
	session := &linkedin.Session{}
	params := &MockParams{
		params: map[string]string{
			"code": "authorization_code",
		},
	}

	t.Run("happy path", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := linkedinProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"test_token","expires_in":3600, "refresh_token":"refresh_token"}`)),
		}, nil)
		token, err := session.Authorize(p, params)
		require.NoError(t, err)
		assert.Equal(t, "test_token", token)
		assert.Equal(t, session.AccessToken, "test_token")
		assert.WithinDuration(t, session.ExpiresAt, time.Now().Add(3600*time.Second), 1*time.Second)
		assert.Equal(t, session.RefreshToken, "refresh_token")
	})

	t.Run("error on request", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := linkedinProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{}, errors.New("request error"))
		_, err := session.Authorize(p, params)
		require.Error(t, err)
	})

	t.Run("non-200 status code", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := linkedinProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(strings.NewReader(``)),
		}, nil)
		_, err := session.Authorize(p, params)
		require.Error(t, err)
	})

	t.Run("error on response decode", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := linkedinProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`not a json`)),
		}, nil)
		_, err := session.Authorize(p, params)
		require.Error(t, err)
	})

	t.Run("error code in response", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := linkedinProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"code":1,"msg":"error message"}`)),
		}, nil)
		_, err := session.Authorize(p, params)
		require.Error(t, err)
	})
}
