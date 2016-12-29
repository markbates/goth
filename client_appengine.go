// +build appengine

package goth

import (
	"net/http"

	"golang.org/x/net/context"
	"google.golang.org/appengine/urlfetch"
)

// Provider implementations should use this method for making outbound HTTP
// requests.
var HTTPClient = func(ctx context.Context) (*http.Client, error) {
	return urlfetch.Client(ctx), nil
}
