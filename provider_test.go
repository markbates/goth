package goth_test

import (
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/faux"
	"github.com/stretchr/testify/assert"
)

func Test_UseProviders(t *testing.T) {
	a := assert.New(t)

	provider := &faux.Provider{}
	goth.UseProviders(provider)
	a.Equal(len(goth.GetProviders()), 1)
	a.Equal(goth.GetProviders()[provider.Name()], provider)
	goth.ClearProviders()
}

func Test_GetProvider(t *testing.T) {
	a := assert.New(t)

	provider := &faux.Provider{}
	goth.UseProviders(provider)

	p, err := goth.GetProvider(provider.Name())
	a.NoError(err)
	a.Equal(p, provider)

	_, err = goth.GetProvider("unknown")
	a.Error(err)
	a.Equal(err.Error(), "no provider for unknown exists")
	goth.ClearProviders()
}

func Test_CustomResolver(t *testing.T) {
	a := assert.New(t)
	resolver := &CustomResolver{}
	goth.SetProviderResolver(resolver)
	p, err := goth.GetProvider("faux")
	a.NoError(err)
	a.Equal(len(goth.GetProviders()), 1)
	a.NotNil(p)

	p, err = goth.GetProvider("unknown")
	a.NoError(err)
	a.Nil(p)

	goth.ClearProviders()
}

type CustomResolver struct{}

func (r CustomResolver) Get(name string) (goth.Provider, error) {
	// you can load this from a database or something
	if name != "faux" {
		return nil, nil
	}
	return &faux.Provider{}, nil
}

func (r CustomResolver) GetAll() goth.Providers {
	// you can load this from a database or something
	return goth.Providers{
		"faux": &faux.Provider{},
	}
}
