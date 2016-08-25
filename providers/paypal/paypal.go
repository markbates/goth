// Package paypal implements the OAuth2 protocol for authenticating users through paypal.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package paypal

import (
	"bytes"
	"encoding/json"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

const (
	sandox string = "sandbox"
	envKey string = "PAYPAL_ENV"

	//Endpoints for paypal sandbox env
	authURLSandbox         string = "https://www.sandbox.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize"
	tokenURLSandbox        string = "https://www.sandbox.paypal.com/webapps/auth/protocol/openidconnect/v1/tokenservice"
	endpointProfileSandbox string = "https://www.sandbox.paypal.com/webapps/auth/protocol/openidconnect/v1/userinfo"

	//Endpoints for paypal production env
	authURLProduction         string = "https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize"
	tokenURLProduction        string = "https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/tokenservice"
	endpointProfileProduction string = "https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/userinfo"
)

// Provider is the implementation of `goth.Provider` for accessing Paypal.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// New creates a new Paypal provider and sets up important connection details.
// You should always call `paypal.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "paypal"
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

	paypalEnv := os.Getenv(envKey)

	profileEndPoint := ""

	if paypalEnv != "" && paypalEnv == sandox {
		profileEndPoint = endpointProfileSandbox
	} else {
		profileEndPoint = endpointProfileProduction
	}

	response, err := http.Get(profileEndPoint + "?schema=openid&access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}
	defer response.Body.Close()

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

func newConfig(provider *Provider, scopes []string) *oauth2.Config {

	paypalEnv := os.Getenv(envKey)

	authURL := ""
	tokenURL := ""

	if paypalEnv != "" && paypalEnv == sandox {
		authURL = authURLSandbox
		tokenURL = tokenURLSandbox
	} else {
		authURL = authURLProduction
		tokenURL = tokenURLProduction
	}

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

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(oauth2.NoContext, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
