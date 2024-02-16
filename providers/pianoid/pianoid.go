package pianoid

import (
	"errors"
	"fmt"
	"net/http"

	jwtgo "github.com/golang-jwt/jwt"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

var (
	// AuthURL ID auth url
	AuthURL = "https://sandbox.piano.io/id"
	// TokenURL vx token url
	TokenURL = "https://sandbox.piano.io/id/api/v1/identity/vxauth/token"
)

// New creates a new Piano provider, and sets up important connection details.
// You should always call `github.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "pianoid",
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Piano.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	debug        bool
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client asdf
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the github package.
func (p *Provider) Debug(debug bool) { p.debug = debug }

// BeginAuth asks Piano for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Piano and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}
	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}
	/// Decode The token

	token, _ := jwtgo.Parse(user.AccessToken, func(token *jwtgo.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwtgo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte("XXX"), nil
	})
	// Token could not be parsed. like it is not signed or tampered
	// if it is failed AND AllowInvalid is not specified -> continue
	claims := token.Claims.(jwtgo.MapClaims)
	user.Email = claims["email"].(string)
	user.FirstName = claims["given_name"].(string)
	user.LastName = claims["family_name"].(string)
	user.UserID = claims["sub"].(string)
	user.RawData = claims

	/// Fetch Profile Details or extract access token
	return user, nil
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

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
}

//RefreshToken refresh token is not provided by github
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by pianoid")
}

//RefreshTokenAvailable refresh token is not provided by github
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
