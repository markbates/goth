// Package reddit implements the OAuth2 protocol for authenticating users through reddit.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package reddit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
)

const (
	authURL      string = "https://www.reddit.com/api/v1/authorize"
	tokenURL     string = "https://www.reddit.com/api/v1/access_token"
	endpointUser string = "https://oauth.reddit.com/api/v1/me"
)

// Provider is the implementation of `goth.Provider` for accessing Reddit.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	userAgent    string
}

// New creates a new Reddit provider and sets up important connection details.
// You should always call `reddit.New` to get a new provider.  Never try to
// create one manually.
// Reddit always responds with 429 status code unless the correct User-Agent is specified.
// https://github.com/reddit-archive/reddit/wiki/API#rules
// userAgent should be something unique and descriptive, including the target platform,
// a unique application identifier, a version string, and your username as contact information,
// in the following format: <platform>:<app ID>:<version string> (by /u/<reddit username>)
func New(clientKey, secret, callbackURL, userAgent string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "reddit",
		userAgent:    userAgent,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// addUserAgentTransport implements http.RoundTripper and adds `User-Agent` header to the request.
type addUserAgentTransport struct {
	rt        http.RoundTripper
	userAgent string
}

// RoundTrip adds `User-Agent` header to the request.
func (addHeader addUserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", addHeader.userAgent)
	return addHeader.rt.RoundTrip(req)
}

// newAddUserAgentTransport creates addUserAgentTransport.
func newAddUserAgentTransport(rt http.RoundTripper, userAgent string) addUserAgentTransport {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return addUserAgentTransport{rt: rt, userAgent: userAgent}
}

// Client returns a pointer to http.Client setting some client fallback.
func (p *Provider) Client() *http.Client {
	client := goth.HTTPClientWithFallBack(p.HTTPClient)
	client.Transport = newAddUserAgentTransport(client.Transport, p.userAgent)
	return client
}

// Debug is a no-op for the Reddit package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks reddit for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to reddit and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	c := p.Client()
	req, err := http.NewRequest("GET", endpointUser, nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", "Bearer "+sess.AccessToken)

	response, err := c.Do(req)
	if response != nil {
		defer response.Body.Close()
	}

	if err != nil {
		return user, err
	}

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID      string `json:"id"`
		IconImg string `json:"icon_img"`
		Name    string `json:"name"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.UserID = u.ID
	user.NickName = u.Name
	user.Name = u.Name
	user.AvatarURL = u.IconImg
	return nil
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
