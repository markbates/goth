package lark_test

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/lark"
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

func Test_Implements_Session(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	s := &lark.Session{}

	a.Implements((*goth.Session)(nil), s)
}

func Test_GetAuthURL(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		session := &lark.Session{
			AuthURL: "https://auth.url",
		}
		url, err := session.GetAuthURL()
		assert.NoError(t, err)
		assert.Equal(t, "https://auth.url", url)
	})

	t.Run("missing AuthURL", func(t *testing.T) {
		session := &lark.Session{}
		_, err := session.GetAuthURL()
		assert.Error(t, err)
	})
}

func Test_Marshal(t *testing.T) {
	session := &lark.Session{
		AuthURL:     "https://auth.url",
		AccessToken: "access_token",
	}
	marshaled := session.Marshal()
	assert.Contains(t, marshaled, "https://auth.url")
	assert.Contains(t, marshaled, "access_token")
}

func Test_Authorize(t *testing.T) {
	session := &lark.Session{}
	params := &MockParams{
		params: map[string]string{
			"code": "authorization_code",
		},
	}

	t.Run("error on request", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{}, errors.New("request error"))
		_, err := session.Authorize(p, params)
		require.Error(t, err)
	})

	t.Run("non-200 status code", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusForbidden,
			Body:       ioutil.NopCloser(strings.NewReader(``)),
		}, nil)
		_, err := session.Authorize(p, params)
		require.Error(t, err)
	})

	t.Run("error on response decode", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`not a json`)),
		}, nil)
		_, err := session.Authorize(p, params)
		require.Error(t, err)
	})

	t.Run("error code in response", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"code":1,"msg":"error message"}`)),
		}, nil)
		_, err := session.Authorize(p, params)
		require.Error(t, err)
	})
}
