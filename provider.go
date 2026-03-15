package goth

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

// Provider needs to be implemented for each 3rd party authentication provider
// e.g. Facebook, Twitter, etc...
type Provider interface {
	Name() string
	SetName(name string)
	BeginAuth(state string) (Session, error)
	UnmarshalSession(string) (Session, error)
	FetchUser(Session) (User, error)
	Debug(bool)
	RefreshToken(refreshToken string) (*oauth2.Token, error) // Get new access token based on the refresh token
	RefreshTokenAvailable() bool                             // Refresh token is provided by auth provider or not
}

// LogoutProvider is an optional interface that providers can implement to
// support RP-Initiated Logout (e.g. OpenID Connect end_session_endpoint).
// Use a type assertion to check if a provider supports logout:
//
//	if lp, ok := provider.(goth.LogoutProvider); ok {
//	    logoutURL, err := lp.EndSessionURL(idToken, redirectURL, state)
//	}
type LogoutProvider interface {
	// EndSessionURL returns the URL to redirect the user to for provider-side logout.
	// Parameters follow the OpenID Connect RP-Initiated Logout spec:
	//   - idTokenHint: the ID token previously issued to the user (recommended)
	//   - postLogoutRedirectURI: where to redirect after logout (optional, must be registered)
	//   - state: opaque value for CSRF protection (optional)
	// See https://openid.net/specs/openid-connect-rpinitiated-1_0.html
	EndSessionURL(idTokenHint, postLogoutRedirectURI, state string) (string, error)
}

const NoAuthUrlErrorMessage = "an AuthURL has not been set"

// Providers is the list of known/available providers.
type Providers map[string]Provider

var (
	providersHat sync.RWMutex
	providers    = Providers{}
)

// UseProviders adds a list of available providers for use with Goth.
// Can be called multiple times. If you pass the same provider more
// than once, the last will be used.
func UseProviders(viders ...Provider) {
	providersHat.Lock()
	defer providersHat.Unlock()

	for _, provider := range viders {
		providers[provider.Name()] = provider
	}
}

// GetProviders returns a list of all the providers currently in use.
func GetProviders() Providers {
	return providers
}

// GetProvider returns a previously created provider. If Goth has not
// been told to use the named provider it will return an error.
func GetProvider(name string) (Provider, error) {
	providersHat.RLock()
	provider := providers[name]
	providersHat.RUnlock()
	if provider == nil {
		return nil, fmt.Errorf("no provider for %s exists", name)
	}
	return provider, nil
}

// ClearProviders will remove all providers currently in use.
// This is useful, mostly, for testing purposes.
func ClearProviders() {
	providersHat.Lock()
	defer providersHat.Unlock()

	providers = Providers{}
}

// ContextForClient provides a context for use with oauth2.
func ContextForClient(h *http.Client) context.Context {
	if h == nil {
		return oauth2.NoContext
	}
	return context.WithValue(oauth2.NoContext, oauth2.HTTPClient, h)
}

// HTTPClientWithFallBack to be used in all fetch operations.
func HTTPClientWithFallBack(h *http.Client) *http.Client {
	if h != nil {
		return h
	}
	return http.DefaultClient
}
