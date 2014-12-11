package goth

import "fmt"

// Provider needs to be implemented for each 3rd party authentication provider
// e.g. Facebook, Twitter, etc...
type Provider interface {
	Name() string
	BeginAuth() (Session, error)
	UnmarshalSession(string) (Session, error)
	FetchUser(Session) (User, error)
	Debug(bool)
}

// Providers is list of known/available providers.
type Providers map[string]Provider

var providers = Providers{}

// Add a new provider to the providers map
func (p *Providers) UpdateProviders(viders *Provider) {
	p = append(p, viders)
}

// Delete a provider from the providers map
func (p *Providers) DelProvider(name string) {
	delete(p, name)
}

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
