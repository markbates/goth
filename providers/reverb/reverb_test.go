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
	"github.com/stretchr/testify/require"
)

func Test_New(t *testing.T) {
	t.Parallel()

	r := require.New(t)
	p := provider()

	r.Equal(os.Getenv("REVERB_KEY"), p.ClientKey)
	r.Equal(os.Getenv("REVERB_SECRET"), p.Secret)
	r.Equal("/foo", p.CallbackURL)
	r.Equal("reverb", p.Name())
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	r.Implements((*goth.Provider)(nil), provider())
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := provider()
	session, err := p.BeginAuth("state")
	r.NoError(err)

	s := session.(*reverb.Session)
	r.Contains(s.AuthURL, "reverb.com/oauth/authorize")
}

func Test_BeginAuthInitializesConfig(t *testing.T) {
	t.Parallel()
	p := &reverb.Provider{}

	session, err := p.BeginAuth("state")
	r := require.New(t)
	r.NoError(err)
	r.NotNil(session)
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	r := require.New(t)

	p := provider()
	session, err := p.UnmarshalSession(`{"AuthURL":"https://reverb.com/oauth/authorize","AccessToken":"token"}`)
	r.NoError(err)

	s := session.(*reverb.Session)
	r.Equal("https://reverb.com/oauth/authorize", s.AuthURL)
	r.Equal("token", s.AccessToken)
}

func Test_SetName(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := staticProvider()
	p.SetName("custom")

	r.Equal("custom", p.Name())
}

func Test_Client(t *testing.T) {
	t.Parallel()

	t.Run("nil provider returns default client", func(t *testing.T) {
		r := require.New(t)
		var p *reverb.Provider
		r.Equal(http.DefaultClient, p.Client())
	})

	t.Run("falls back to default client", func(t *testing.T) {
		r := require.New(t)
		p := staticProvider()
		r.Equal(http.DefaultClient, p.Client())
	})

	t.Run("returns provided client", func(t *testing.T) {
		r := require.New(t)
		custom := &http.Client{}
		p := staticProvider()
		p.HTTPClient = custom

		r.Equal(custom, p.Client())
	})
}

func Test_Debug(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := staticProvider()

	r.NotPanics(func() {
		var nilProvider *reverb.Provider
		nilProvider.Debug(true)
		p.Debug(true)
		p.Debug(false)
	})
}

func Test_FetchUserRequiresAccessToken(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := staticProvider()
	session := &reverb.Session{}

	user, err := p.FetchUser(session)

	r.Error(err)
	r.Empty(user.AccessToken)
	r.Equal(p.Name(), user.Provider)
}

func Test_FetchUserClientError(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("boom")
		}),
	}
	session := &reverb.Session{AccessToken: "token"}

	user, err := p.FetchUser(session)

	r.Error(err)
	r.Empty(user.Email)
}

func Test_FetchUserClientErrorWithResponse(t *testing.T) {
	t.Parallel()
	r := require.New(t)
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

	r.Error(err)
	r.Empty(user.Email)
}

func Test_FetchUserNonOKResponse(t *testing.T) {
	t.Parallel()
	r := require.New(t)
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

	r.Error(err)
}

func Test_FetchUserNilSession(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := staticProvider()

	user, err := p.FetchUser(nil)
	r.Error(err)
	r.Equal(p.Name(), user.Provider)
}

func Test_FetchUserInvalidSessionType(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := staticProvider()

	user, err := p.FetchUser(bogusSession{})
	r.Error(err)
	r.Equal(p.Name(), user.Provider)
}

func Test_FetchUserReadBodyError(t *testing.T) {
	t.Parallel()
	r := require.New(t)
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
	r.Error(err)
}

func Test_FetchUserEmptyBody(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       nil,
				Header:     make(http.Header),
			}, nil
		}),
	}
	session := &reverb.Session{AccessToken: "token"}

	_, err := p.FetchUser(session)
	r.Error(err)
}

func Test_FetchUserRawDataUnmarshalError(t *testing.T) {
	t.Parallel()
	r := require.New(t)
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
	r.Error(err)
}

func Test_FetchUserAccountDecodeError(t *testing.T) {
	t.Parallel()
	r := require.New(t)
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
	r.Error(err)
}

func Test_FetchUserSuccess(t *testing.T) {
	t.Parallel()
	r := require.New(t)
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
			r.Equal("Bearer token", req.Header.Get("Authorization"))
			r.Equal("application/json", req.Header.Get("Accept"))
			r.Equal("3.0", req.Header.Get("Accept-Version"))
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
	r.NoError(err)

	r.Equal("jane@example.com", user.Email)
	r.Equal("Jane Doe", user.Name)
	r.Equal("Jane", user.FirstName)
	r.Equal("Doe", user.LastName)
	r.Equal("proslug", user.NickName)
	r.Equal("uuid-123", user.UserID)
	r.Equal("Cool Shop", user.Description)
	r.Equal("https://example.com/avatar.png", user.AvatarURL)
	r.Equal("US", user.Location)
	r.Equal(p.Name(), user.Provider)
	r.NotNil(user.RawData)
}

func Test_FetchUserSuccessWithNumericID(t *testing.T) {
	t.Parallel()
	r := require.New(t)
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
	r.NoError(err)

	r.Equal("june@example.com", user.Email)
	r.Equal("June Carter", user.Name)
	r.Equal("north-slug", user.NickName)
	r.Equal("987", user.UserID)
	r.Equal("North Shop", user.Description)
	r.Equal("https://example.com/north.png", user.AvatarURL)
	r.Equal("CA", user.Location)
}

func Test_RefreshTokenAvailable(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := staticProvider()

	r.True(p.RefreshTokenAvailable())
}

func Test_RefreshTokenMissingConfig(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := &reverb.Provider{}

	token, err := p.RefreshToken("refresh-token")
	r.Nil(token)
	r.Error(err)
}

func Test_RefreshToken(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := staticProvider()
	p.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			r.Equal(http.MethodPost, req.Method)
			r.Equal("https://reverb.com/oauth/access_token", req.URL.String())
			body, err := io.ReadAll(req.Body)
			r.NoError(err)
			r.NoError(req.Body.Close())
			r.Contains(string(body), "grant_type=refresh_token")
			r.Contains(string(body), "refresh_token=refresh-token")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-token","token_type":"bearer","expires_in":3600}`)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	token, err := p.RefreshToken("refresh-token")
	r.NoError(err)
	r.NotNil(token)
	r.Equal("new-token", token.AccessToken)
}

func Test_NewWithScopes(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	p := reverb.New("key", "secret", "callback", "one", "two")

	session, err := p.BeginAuth("state")
	r.NoError(err)

	authURL := session.(*reverb.Session).AuthURL
	parsed, err := url.Parse(authURL)
	r.NoError(err)

	scopes := parsed.Query().Get("scope")
	r.Contains(scopes, "one")
	r.Contains(scopes, "two")
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

type bogusSession struct{}

func (errorReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("read error")
}

func (errorReadCloser) Close() error {
	return nil
}

func (bogusSession) GetAuthURL() (string, error) { return "", nil }

func (bogusSession) Marshal() string { return "" }

func (bogusSession) Authorize(goth.Provider, goth.Params) (string, error) { return "", nil }

func Test_NilProviderSafety(t *testing.T) {
	t.Parallel()
	r := require.New(t)
	var p *reverb.Provider

	r.NotPanics(func() { _ = p.Name() })
	r.NotPanics(func() { p.SetName("whatever") })
	r.NotPanics(func() { _ = p.Client() })
	r.NotPanics(func() { p.Debug(true) })

	session, err := p.BeginAuth("state")
	r.Nil(session)
	r.Error(err)

	user, err := p.FetchUser(&reverb.Session{})
	r.Error(err)
	r.Empty(user.Email)

	token, err := p.RefreshToken("refresh")
	r.Nil(token)
	r.Error(err)
	r.False(p.RefreshTokenAvailable())
}
