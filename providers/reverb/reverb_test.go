package reverb_test

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/reverb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)
	p := provider()

	a.Equal(os.Getenv("REVERB_KEY"), p.ClientKey)
	a.Equal(os.Getenv("REVERB_SECRET"), p.Secret)
	a.Equal("/foo", p.CallbackURL)
	a.Equal("reverb", p.Name())
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
	session, err := p.BeginAuth("state")
	a.NoError(err)

	s := session.(*reverb.Session)
	a.Contains(s.AuthURL, "reverb.com/oauth/authorize")
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://reverb.com/oauth/authorize","AccessToken":"token"}`)
	a.NoError(err)

	s := session.(*reverb.Session)
	a.Equal("https://reverb.com/oauth/authorize", s.AuthURL)
	a.Equal("token", s.AccessToken)
}

func Test_SetName(t *testing.T) {
	t.Parallel()
	p := staticProvider()
	p.SetName("custom")

	assert.Equal(t, "custom", p.Name())
}

func Test_Client(t *testing.T) {
	t.Parallel()

	t.Run("falls back to default client", func(t *testing.T) {
		p := staticProvider()
		assert.Equal(t, http.DefaultClient, p.Client())
	})

	t.Run("returns provided client", func(t *testing.T) {
		custom := &http.Client{}
		p := staticProvider()
		p.HTTPClient = custom

		assert.Equal(t, custom, p.Client())
	})
}

func Test_Debug(t *testing.T) {
	t.Parallel()
	p := staticProvider()

	assert.NotPanics(t, func() {
		p.Debug(true)
		p.Debug(false)
	})
}

func Test_FetchUserRequiresAccessToken(t *testing.T) {
	t.Parallel()
	p := staticProvider()
	session := &reverb.Session{}

	user, err := p.FetchUser(session)

	assert.Error(t, err)
	assert.Empty(t, user.AccessToken)
	assert.Equal(t, p.Name(), user.Provider)
}

func Test_FetchUserClientError(t *testing.T) {
	t.Parallel()
	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("boom")
		}),
	}
	session := &reverb.Session{AccessToken: "token"}

	user, err := p.FetchUser(session)

	assert.Error(t, err)
	assert.Empty(t, user.Email)
}

func Test_FetchUserClientErrorWithResponse(t *testing.T) {
	t.Parallel()
	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := &http.Response{
				StatusCode: http.StatusFound,
				Body:       io.NopCloser(strings.NewReader("redirect")),
				Header: http.Header{
					"Location": []string{"https://example.com/next"},
				},
			}
			return resp, nil
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("boom")
		},
	}
	session := &reverb.Session{AccessToken: "token"}

	user, err := p.FetchUser(session)

	assert.Error(t, err)
	assert.Empty(t, user.Email)
}

func Test_FetchUserNonOKResponse(t *testing.T) {
	t.Parallel()
	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Body:       io.NopCloser(strings.NewReader("bad gateway")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	session := &reverb.Session{AccessToken: "token"}

	_, err := p.FetchUser(session)

	assert.Error(t, err)
}

func Test_FetchUserReadBodyError(t *testing.T) {
	t.Parallel()
	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errorReadCloser{},
				Header:     make(http.Header),
			}, nil
		}),
	}
	session := &reverb.Session{AccessToken: "token"}

	_, err := p.FetchUser(session)
	assert.Error(t, err)
}

func Test_FetchUserRawDataUnmarshalError(t *testing.T) {
	t.Parallel()
	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	session := &reverb.Session{AccessToken: "token"}

	_, err := p.FetchUser(session)
	assert.Error(t, err)
}

func Test_FetchUserAccountDecodeError(t *testing.T) {
	t.Parallel()
	body := `{
		"first_name": "Jane",
		"last_name": "Doe",
		"email": "jane@example.com",
		"user_id": {"nested": "value"}
	}`

	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	session := &reverb.Session{AccessToken: "token"}

	_, err := p.FetchUser(session)
	assert.Error(t, err)
}

func Test_FetchUserSuccess(t *testing.T) {
	t.Parallel()
	body := `{
		"first_name": "Jane",
		"last_name": "Doe",
		"email": "jane@example.com",
		"profile_slug": "proslug",
		"uuid": "uuid-123",
		"shipping_region_code": "US",
		"shop": {"name": "Cool Shop", "slug": "shop-slug"},
		"_links": {"avatar": {"href": "https://example.com/avatar.png"}}
	}`

	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))
			assert.Equal(t, "application/json", req.Header.Get("Accept"))
			assert.Equal(t, "3.0", req.Header.Get("Accept-Version"))
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	session := &reverb.Session{
		AccessToken:  "token",
		RefreshToken: "refresh",
	}

	user, err := p.FetchUser(session)
	require.NoError(t, err)

	assert.Equal(t, "jane@example.com", user.Email)
	assert.Equal(t, "Jane Doe", user.Name)
	assert.Equal(t, "Jane", user.FirstName)
	assert.Equal(t, "Doe", user.LastName)
	assert.Equal(t, "proslug", user.NickName)
	assert.Equal(t, "uuid-123", user.UserID)
	assert.Equal(t, "Cool Shop", user.Description)
	assert.Equal(t, "https://example.com/avatar.png", user.AvatarURL)
	assert.Equal(t, "US", user.Location)
	assert.Equal(t, p.Name(), user.Provider)
	require.NotNil(t, user.RawData)
}

func Test_FetchUserSuccessWithNumericID(t *testing.T) {
	t.Parallel()
	body := `{
		"first_name": "June",
		"last_name": "Carter",
		"email": "june@example.com",
		"profile_slug": "",
		"uuid": "",
		"user_id": 987,
		"shipping_region_code": "CA",
		"shop": {"name": "North Shop", "slug": "north-slug"},
		"_links": {"avatar": {"href": "https://example.com/north.png"}}
	}`

	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
	session := &reverb.Session{AccessToken: "token"}

	user, err := p.FetchUser(session)
	require.NoError(t, err)

	assert.Equal(t, "june@example.com", user.Email)
	assert.Equal(t, "June Carter", user.Name)
	assert.Equal(t, "north-slug", user.NickName)
	assert.Equal(t, "987", user.UserID)
	assert.Equal(t, "North Shop", user.Description)
	assert.Equal(t, "https://example.com/north.png", user.AvatarURL)
	assert.Equal(t, "CA", user.Location)
}

func Test_RefreshTokenAvailable(t *testing.T) {
	t.Parallel()
	p := staticProvider()

	assert.True(t, p.RefreshTokenAvailable())
}

func Test_RefreshToken(t *testing.T) {
	t.Parallel()
	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, http.MethodPost, req.Method)
			require.Equal(t, "https://reverb.com/oauth/access_token", req.URL.String())
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.NoError(t, req.Body.Close())
			require.Contains(t, string(body), "grant_type=refresh_token")
			require.Contains(t, string(body), "refresh_token=refresh-token")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-token","token_type":"bearer","expires_in":3600}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	token, err := p.RefreshToken("refresh-token")
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "new-token", token.AccessToken)
}

func Test_NewWithScopes(t *testing.T) {
	t.Parallel()
	p := reverb.New("key", "secret", "callback", "one", "two")

	session, err := p.BeginAuth("state")
	require.NoError(t, err)

	authURL := session.(*reverb.Session).AuthURL
	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	scopes := parsed.Query().Get("scope")
	assert.Contains(t, scopes, "one")
	assert.Contains(t, scopes, "two")
}

func provider() *reverb.Provider {
	return reverb.New(os.Getenv("REVERB_KEY"), os.Getenv("REVERB_SECRET"), "/foo")
}

func staticProvider(scopes ...string) *reverb.Provider {
	return reverb.New("client", "secret", "https://callback", scopes...)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type errorReadCloser struct{}

func (errorReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("read error")
}

func (errorReadCloser) Close() error {
	return nil
}
