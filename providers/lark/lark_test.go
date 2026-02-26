package lark_test

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/markbates/goth/providers/lark"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockedHTTPClient struct {
	mock.Mock
}

func (m *MockedHTTPClient) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Mock.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := larkProvider()

	a.Equal(p.ClientKey, os.Getenv("LARK_APP_ID"))
	a.Equal(p.Secret, os.Getenv("LARK_APP_SECRET"))
	a.Equal(p.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := larkProvider()
	session, err := p.BeginAuth("test_state")
	s := session.(*lark.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://open.feishu.cn/open-apis/authen/v1/authorize")
	a.Contains(s.AuthURL, "app_id="+os.Getenv("LARK_APP_ID"))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, fmt.Sprintf("redirect_uri=%s", url.QueryEscape("/foo")))
}

func Test_GetAppAccessToken(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"code":0,"msg":"ok","app_access_token":"test_token","expire":3600}`)),
		}, nil)

		err := p.GetAppAccessToken()
		assert.NoError(t, err)
	})

	t.Run("error on request", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{}, errors.New("request error"))

		err := p.GetAppAccessToken()
		assert.Error(t, err)
	})

	t.Run("non-200 status code", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusForbidden,
			Body:       ioutil.NopCloser(strings.NewReader(``)),
		}, nil)

		err := p.GetAppAccessToken()
		assert.Error(t, err)
	})

	t.Run("error on response decode", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`not a json`)),
		}, nil)

		err := p.GetAppAccessToken()
		assert.Error(t, err)
	})

	t.Run("error code in response", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}

		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"code":1,"msg":"error message"}`)),
		}, nil)

		err := p.GetAppAccessToken()
		assert.Error(t, err)
	})
}

func Test_FetchUser(t *testing.T) {
	session := &lark.Session{
		AccessToken: "user_access_token",
	}

	t.Run("happy path", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       ioutil.NopCloser(strings.NewReader(`{"code":0,"msg":"ok","data":{"user_id":"test_user_id","name":"test_name","avatar_url":"test_avatar_url","enterprise_email":"test_email"}}`)),
		}, nil)
		user, err := p.FetchUser(session)
		require.NoError(t, err)
		assert.Equal(t, user.UserID, "test_user_id")
		assert.Equal(t, user.Name, "test_name")
		assert.Equal(t, user.AvatarURL, "test_avatar_url")
		assert.Equal(t, user.Email, "test_email")
	})
	t.Run("error on request", func(t *testing.T) {
		mockClient := new(MockedHTTPClient)
		p := larkProvider()
		p.HTTPClient = &http.Client{Transport: mockClient}
		mockClient.On("RoundTrip", mock.Anything).Return(&http.Response{}, errors.New("request error"))
		_, err := p.FetchUser(session)
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
		_, err := p.FetchUser(session)
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
		_, err := p.FetchUser(session)
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
		_, err := p.FetchUser(session)
		require.Error(t, err)
	})
}

func larkProvider() *lark.Provider {
	return lark.New(os.Getenv("LARK_APP_ID"), os.Getenv("LARK_APP_SECRET"), "/foo")
}
