// Package paypal implements the OAuth2 protocol for authenticating users through paypal.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package paypal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	sandbox string = "sandbox"
	envKey  string = "PAYPAL_ENV"

	// Endpoints for paypal sandbox env
	authURLSandbox         string = "https://www.sandbox.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize"
	tokenURLSandbox        string = "https://www.sandbox.paypal.com/webapps/auth/protocol/openidconnect/v1/tokenservice"
	endpointProfileSandbox string = "https://www.sandbox.paypal.com/webapps/auth/protocol/openidconnect/v1/userinfo"

	// Endpoints for paypal production env
	authURLProduction         string = "https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize"
	tokenURLProduction        string = "https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/tokenservice"
	endpointProfileProduction string = "https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/userinfo"
)

// Provider is the implementation of `goth.Provider` for accessing Paypal.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	profileURL   string
}

// New creates a new Paypal provider and sets up important connection details.
// You should always call `paypal.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	paypalEnv := os.Getenv(envKey)

	authURL := authURLProduction
	tokenURL := tokenURLProduction
	profileEndPoint := endpointProfileProduction

	if paypalEnv == sandbox {
		authURL = authURLSandbox
		tokenURL = tokenURLSandbox
		profileEndPoint = endpointProfileSandbox
	}

	return NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileEndPoint, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "paypal",
		profileURL:   profileURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
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

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the paypal package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Paypal for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Paypal and access basic information about the user.
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

	response, err := p.Client().Get(p.profileURL + "?schema=openid&access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := io.ReadAll(response.Body)
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

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
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
	} else {
		c.Scopes = append(c.Scopes, "profile", "email")
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name    string `json:"name"`
		Address struct {
			Locality string `json:"locality"`
		} `json:"address"`
		Email string `json:"email"`
		ID    string `json:"user_id"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = u.Email
	user.Name = u.Name
	user.UserID = u.ID
	user.Location = u.Address.Locality
	return nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
