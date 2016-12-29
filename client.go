// +build !appengine

package goth

import (
	"net/http"

	"golang.org/x/net/context"
)

// Provider implementations should use this method for making outbound HTTP
// requests.
var HTTPClient = func(ctx context.Context) (*http.Client, error) {
	return http.DefaultClient, nil
}
