//go:build !go1.22
// +build !go1.22

package gothic

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	"github.com/markbates/goth"
)

// GetProviderName is a function used to get the name of a provider
// for a given request. By default, this provider is fetched from
// the URL query string. If you provide it in a different way,
// assign your own function to this variable that returns the provider
// name for your request.
var GetProviderName = getProviderName

func getProviderName(req *http.Request) (string, error) {
	// try to get it from the url param "provider"
	if p := req.URL.Query().Get("provider"); p != "" {
		return p, nil
	}

	// try to get it from the url param ":provider"
	if p := req.URL.Query().Get(":provider"); p != "" {
		return p, nil
	}

	// try to get it from the context's value of "provider" key
	if p, ok := mux.Vars(req)["provider"]; ok {
		return p, nil
	}

	//  try to get it from the go-context's value of "provider" key
	if p, ok := req.Context().Value("provider").(string); ok {
		return p, nil
	}

	// try to get it from the url param "provider", when req is routed through 'chi'
	if p := chi.URLParam(req, "provider"); p != "" {
		return p, nil
	}

	// try to get it from the go-context's value of providerContextKey key
	if p, ok := req.Context().Value(ProviderParamKey).(string); ok {
		return p, nil
	}

	// As a fallback, loop over the used providers, if we already have a valid session for any provider (ie. user has already begun authentication with a provider), then return that provider name
	providers := goth.GetProviders()
	session, _ := Store.Get(req, SessionName)
	for _, provider := range providers {
		p := provider.Name()
		value := session.Values[p]
		if _, ok := value.(string); ok {
			return p, nil
		}
	}

	// if not found then return an empty string with the corresponding error
	return "", errors.New("you must select a provider")
}
