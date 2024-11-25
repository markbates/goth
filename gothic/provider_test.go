//go:build go1.22
// +build go1.22

package gothic_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/markbates/goth/gothic"
	"github.com/stretchr/testify/assert"
)

func Test_GetAuthURL122(t *testing.T) {
	a := assert.New(t)

	res := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/auth", nil)
	a.NoError(err)
	req.SetPathValue("provider", "faux")

	u, err := gothic.GetAuthURL(res, req)
	a.NoError(err)

	// Check that we get the correct auth URL with a state parameter
	parsed, err := url.Parse(u)
	a.NoError(err)
	a.Equal("http", parsed.Scheme)
	a.Equal("example.com", parsed.Host)
	q := parsed.Query()
	a.Contains(q, "client_id")
	a.Equal("code", q.Get("response_type"))
	a.NotZero(q, "state")

	// Check that if we run GetAuthURL on another request, that request's
	// auth URL has a different state from the previous one.
	req2, err := http.NewRequest("GET", "/auth?provider=faux", nil)
	a.NoError(err)
	req2.SetPathValue("provider", "faux")
	url2, err := gothic.GetAuthURL(httptest.NewRecorder(), req2)
	a.NoError(err)
	parsed2, err := url.Parse(url2)
	a.NoError(err)
	a.NotEqual(parsed.Query().Get("state"), parsed2.Query().Get("state"))
}
