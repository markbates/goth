// Package auth0 implements the OAuth2 protocol for authenticating users through uber.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package auth0

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"fmt"
)

const (
	authEndpoint    string = "/oauth/authorize"
	tokenEndpoint   string = "/oauth/token"
	endpointProfile string = "/userinfo"
	protocol        string = "https://"
)

// Provider is the implementation of `goth.Provider` for accessing Auth0.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	Domain       string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

type auth0UserResp struct {
	Name      string `json:"name"`
	NickName  string `json:"nickname"`
	Email     string `json:"email"`
	UserID    string `json:"user_id"`
	AvatarURL string `json:"picture"`
}

// New creates a new Auth0 provider and sets up important connection details.
// You should always call `auth0.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, auth0Domain string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:           clientKey,
		Secret:              secret,
		CallbackURL:         callbackURL,
		Domain:              auth0Domain,
		providerName:        "auth0",
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

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the auth0 package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Auth0 for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Auth0 and access basic information about the user.
// the full response will be included in RawData
// https://auth0.com/docs/api/authentication#get-user-info

func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	userProfileURL := protocol + p.Domain + endpointProfile
	req, err := http.NewRequest("GET", userProfileURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := p.Client().Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	err = userFromReader(resp.Body, &user)
	return user, err
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  protocol + provider.Domain + authEndpoint,
			TokenURL: protocol + provider.Domain + tokenEndpoint,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	} else {
		c.Scopes = append(c.Scopes, "profile", "openid")
	}

	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	var rawData map[string]interface{}

	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	err := json.Unmarshal(buf.Bytes(), &rawData)
	if err != nil {
		return err
	}

	u := auth0UserResp{}
	err = json.Unmarshal(buf.Bytes(), &u)
	if err != nil {
		return err
	}
	user.Email = u.Email
	user.Name = u.Name
	user.NickName = u.NickName
	user.UserID = u.UserID
	user.AvatarURL = u.AvatarURL
	user.RawData = rawData
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
