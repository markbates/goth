package goth_test

import (
	"reflect"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/apple"
	"github.com/markbates/goth/providers/azureadv2"
	"github.com/markbates/goth/providers/faux"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/tiktok"
	"github.com/stretchr/testify/assert"
)

func Test_ConfigProvider(t *testing.T) {
	a := assert.New(t)

	configs := []goth.ProviderConfig{
		&azureadv2.Config{
			ClientKey: "6731de76-14a6-49ae-97bc-6eba6914391e",
			Secret:    "foo",
		},
		&github.Config{
			ClientKey: "6731de76-14a6-49ae-97bc-6eba6914391e",
			Secret:    "foo",
		},
		&tiktok.Config{
			ClientKey: "6731de76-14a6-49ae-97bc-6eba6914391e",
			Secret:    "foo",
		},
		&apple.Config{
			ClientId: "6731de76-14a6-49ae-97bc-6eba6914391e",
			Secret:   "foo",
		},
	}

	callbackURL := "http://localhost:3000/{provider}/callback"

	var providers []goth.Provider
	for _, cfg := range configs {
		cfg.SetCallbackURL(callbackURL)
		provider := cfg.Build()
		providers = append(providers, provider)
		a.Equal(cfg.Name(), provider.Name())
		goth.UseProviders(provider)
	}

	a.Equal(len(goth.GetProviders()), len(configs))

	fieldNames := []string{
		"CallbackURL", "callbackURL",
		"RedirectURL", "redirectURL",
		"RedirectURI", "redirectURI",
	}
	for _, provider := range providers {
		a.Equal(goth.GetProviders()[provider.Name()], provider)
		// Gets provider, reflect the underlying azureadv2.Provider and
		// compares it's callbackURL with the one that was set in azureadv2.Config
		v := reflect.ValueOf(goth.GetProviders()[provider.Name()]).Elem()
		fieldFound := false
		for _, fieldName := range fieldNames {
			f := v.FieldByName(fieldName)
			if f.IsValid() {
				fieldFound = true
				a.Equal(f.String(), callbackURL)
				break
			}
		}
		if !fieldFound {
			t.Fatal("callback/redirect field was not found for " + provider.Name())
		}
	}

	goth.ClearProviders()
}

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
