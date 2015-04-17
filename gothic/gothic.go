/*
Package gothic wraps common behaviour when using Goth. This makes it quick, and easy, to get up
and running with Goth. Of course, if you want complete control over how things flow, in regards
to the authentication process, feel free and use Goth directly.

See https://github.com/markbates/goth/examples/main.go to see this in action.
*/
package gothic

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"golang.org/x/net/context"
)

// SessionName is the key used to access the session store.
const SessionName = "_gothic_session"

// AppKey should be replaced by applications using gothic.
var AppKey = "XDZZYmriq8pJ5k8OKqdDuUFym2e7Im5O1MzdyapfotOnrqQ7ZEdTN9AA7K6aPieC"

// Store can/should be set by applications using gothic. The default is a cookie store.
var Store sessions.Store

func init() {
	if Store == nil {
		Store = sessions.NewCookieStore([]byte(AppKey))
	}
}

/*
BeginAuthHandler is a convienence handler for starting the authentication process.
It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

BeginAuthHandler will redirect the user to the appropriate authentication end-point
for the requested provider.

See https://github.com/markbates/goth/examples/main.go to see this in action.
*/
func BeginAuthHandler(res http.ResponseWriter, req *http.Request) {
	url, err := GetAuthURL(res, req)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(res, err)
		return
	}

	http.Redirect(res, req, url, http.StatusTemporaryRedirect)
}

// GetState gets the state string associated with the given request
// This state is sent to the provider and can be retrieved during the
// callback.
var GetState = func(req *http.Request) string {
	return "state"
}

/*
GetAuthURL starts the authentication process with the requested provided.
It will return a URL that should be used to send users to.

It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

I would recommend using the BeginAuthHandler instead of doing all of these steps
yourself, but that's entirely up to you.
*/
func GetAuthURL(res http.ResponseWriter, req *http.Request) (string, error) {

	providerName, err := GetProviderName(req)
	if err != nil {
		return "", err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", err
	}
	sess, err := provider.BeginAuth(GetState(req))
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	session, _ := Store.Get(req, SessionName)
	session.Values[SessionName] = sess.Marshal()
	err = session.Save(req, res)
	if err != nil {
		return "", err
	}

	return url, err
}

/*
CompleteUserAuth does what it says on the tin. It completes the authentication
process and fetches all of the basic information about the user from the provider.

It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

See https://github.com/markbates/goth/examples/main.go to see this in action.
*/
func CompleteUserAuth(ctx context.Context, res http.ResponseWriter, req *http.Request) (goth.User, error) {

	providerName, err := GetProviderName(req)
	if err != nil {
		return goth.User{}, err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return goth.User{}, err
	}

	session, _ := Store.Get(req, SessionName)

	if session.Values[SessionName] == nil {
		return goth.User{}, errors.New("could not find a matching session for this request")
	}

	sess, err := provider.UnmarshalSession(session.Values[SessionName].(string))
	if err != nil {
		return goth.User{}, err
	}

	_, err = sess.Authorize(ctx, provider, req.URL.Query())

	if err != nil {
		return goth.User{}, err
	}

	return provider.FetchUser(sess)
}

// GetProviderName is a function used to get the name of a provider
// for a given request. By default, this provider is fetched from
// the URL query string. If you provide it in a different way,
// assign your own function to this variable that returns the provider
// name for your request.
var GetProviderName = getProviderName

func getProviderName(req *http.Request) (string, error) {
	provider := req.URL.Query().Get("provider")
	if provider == "" {
		provider = req.URL.Query().Get(":provider")
	}
	if provider == "" {
		return provider, errors.New("you must select a provider")
	}
	return provider, nil
}
