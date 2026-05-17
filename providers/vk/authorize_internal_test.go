package vk

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// tokenServer spins up an httptest.Server that responds to the OAuth2 token
// exchange with the given JSON body, and swaps the package-level tokenURL so
// the provider hits it. The returned cleanup restores the original tokenURL
// and shuts the server down.
func tokenServer(t *testing.T, body string) func() {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	original := tokenURL
	tokenURL = server.URL
	return func() {
		tokenURL = original
		server.Close()
	}
}

func TestAuthorize_PopulatesEmailWhenPresent(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	cleanup := tokenServer(t, `{"access_token":"tok","expires_in":86400,"user_id":1,"email":"user@example.com"}`)
	defer cleanup()

	p := New("key", "secret", "/cb")
	sess, err := p.BeginAuth("state")
	a.NoError(err)
	s := sess.(*Session)

	token, err := s.Authorize(p, url.Values{"code": {"any"}})
	a.NoError(err)
	a.Equal("tok", token)
	a.Equal("user@example.com", s.email)
}

func TestAuthorize_NoErrorWhenEmailMissing(t *testing.T) {
	// Regression test for markbates/goth#338: VK accounts created without an
	// email field omit "email" from the token response. The provider must
	// treat it as optional and not fail the auth flow.
	t.Parallel()
	a := assert.New(t)

	cleanup := tokenServer(t, `{"access_token":"tok","expires_in":86400,"user_id":1}`)
	defer cleanup()

	p := New("key", "secret", "/cb")
	sess, err := p.BeginAuth("state")
	a.NoError(err)
	s := sess.(*Session)

	token, err := s.Authorize(p, url.Values{"code": {"any"}})
	a.NoError(err)
	a.Equal("tok", token)
	a.Equal("", s.email)
}
