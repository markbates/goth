package hubspot

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// These vars define the Authentication and Token URLS for Hubspot.
var (
	AuthURL  = "https://app.hubspot.com/oauth/authorize"
	TokenURL = "https://api.hubapi.com/oauth/v1/token"
)

const (
	userEndpoint = "https://api.hubapi.com/oauth/v1/access-tokens/"
)

type hubspotUser struct {
	Token                     string   `json:"token"`
	User                      string   `json:"user"`
	HubDomain                 string   `json:"hub_domain"`
	Scopes                    []string `json:"scopes"`
	ScopeToScopeGroupPKs      []int    `json:"scope_to_scope_group_pks"`
	TrialScopes               []string `json:"trial_scopes"`
	TrialScopeToScopeGroupPKs []int    `json:"trial_scope_to_scope_group_pks"`
	HubID                     int      `json:"hub_id"`
	AppID                     int      `json:"app_id"`
	ExpiresIn                 int      `json:"expires_in"`
	UserID                    int      `json:"user_id"`
	TokenType                 string   `json:"token_type"`
}

// Provider is the implementation of `goth.Provider` for accessing Hubspot.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new Hubspot provider and sets up important connection details.
// You should always call `hubspot.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "hubspot",
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

// Debug is a no-op for the hubspot package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Hubspot for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Hubspot and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	response, err := p.Client().Get(userEndpoint + url.QueryEscape(user.AccessToken))
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	var u hubspotUser
	if err := json.Unmarshal(responseBytes, &u); err != nil {
		return user, err
	}

	// Extract the user data we got from Google into our goth.User.
	user.Email = u.User
	user.UserID = strconv.Itoa(u.UserID)
	accessTokenExpiration := time.Now()
	if u.ExpiresIn > 0 {
		accessTokenExpiration = accessTokenExpiration.Add(time.Duration(u.ExpiresIn) * time.Second)
	} else {
		accessTokenExpiration = accessTokenExpiration.Add(30 * time.Minute)
	}
	user.ExpiresAt = accessTokenExpiration
	// Google provides other useful fields such as 'hd'; get them from RawData
	if err := json.Unmarshal(responseBytes, &user.RawData); err != nil {
		return user, err
	}

	return user, nil
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  AuthURL,
			TokenURL: TokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		c.Scopes = append(c.Scopes, scopes...)
	}

	return c
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
