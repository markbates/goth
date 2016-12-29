package goth

import (
	"fmt"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// Provider needs to be implemented for each 3rd party authentication provider
// e.g. Facebook, Twitter, etc...
type Provider interface {
	// When implementing a provider, these methods should not make outbound
	// requests.
	Name() string
	UnmarshalSession(string) (Session, error)
	Debug(bool)
	// Refresh token is provided by auth provider or not
	RefreshTokenAvailable() bool

	// These three methods are deprecated. See the appropriate *Ctx replacement.
	BeginAuth(state string) (Session, error)
	FetchUser(Session) (User, error)
	RefreshToken(refreshToken string) (*oauth2.Token, error)

	// These methods are now preferred.
	BeginAuthCtx(ctx context.Context, state string) (Session, error)
	FetchUserCtx(context.Context, Session) (User, error)
	// Get new access token based on the refresh token.
	// Only works if RefreshTokenAvailable() is true
	RefreshTokenCtx(ctx context.Context, refreshToken string) (*oauth2.Token, error)
}

// Providers is list of known/available providers.
type Providers map[string]Provider

var providers = Providers{}

// UseProviders sets a list of available providers for use with Goth.
func UseProviders(viders ...Provider) {
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
	provider := providers[name]
	if provider == nil {
		return nil, fmt.Errorf("no provider for %s exists", name)
	}
	return provider, nil
}

// ClearProviders will remove all providers currently in use.
// This is useful, mostly, for testing purposes.
func ClearProviders() {
	providers = Providers{}
}
