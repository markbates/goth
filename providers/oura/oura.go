// Package oura implements the OAuth protocol for authenticating users through Oura API (for OuraRing).
package oura

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://cloud.ouraring.com/oauth/authorize"
	tokenURL        string = "https://api.ouraring.com/oauth/token"
	endpointProfile string = "https://api.ouraring.com/v1/userinfo"
)

const (
	// ScopeEmail includes email address of the user
	ScopeEmail = "email"
	// ScopePersonal includes personal information (gender, age, height, weight)
	ScopePersonal = "personal"
	// ScopeDaily includes daily summaries of sleep, activity and readiness
	ScopeDaily = "daily"
)

// New creates a new Oura provider (for OuraRing), and sets up important connection details.
// You should always call `oura.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "oura",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Oura API.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client for making requests on the provider
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the oura package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Oura for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Oura and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
		UserID:       s.UserID,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", endpointProfile, nil)
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
		return user, NewAPIError(resp.StatusCode, fmt.Sprintf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode))
	}

	// err = userFromReader(io.TeeReader(resp.Body, os.Stdout), &user)
	err = userFromReader(resp.Body, &user)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		Age    int     `json:"age"`
		Weight float32 `json:"weight"` // kg
		Height int     `json:"height"` // cm
		Gender string  `json:"gender"`
		Email  string  `json:"email"`
		UserID string  `json:"user_id"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	rawData := make(map[string]interface{})

	if u.Age != 0 {
		rawData["age"] = u.Age
	}
	if u.Weight != 0 {
		rawData["weight"] = u.Weight
	}
	if u.Height != 0 {
		rawData["height"] = u.Height
	}
	if u.Gender != "" {
		rawData["gender"] = u.Gender
	}

	user.UserID = u.UserID
	user.Email = u.Email
	if len(rawData) > 0 {
		user.RawData = rawData
	}

	return err
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

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(oauth2.NoContext, token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

// RefreshTokenAvailable refresh token is not provided by oura
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}
