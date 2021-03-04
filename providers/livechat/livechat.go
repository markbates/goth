// Package livechat implements the OAuth protocol for authenticating users through Livechat.
package livechat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
)

const (
	authURL             = "https://accounts.livechat.com"
	tokenURL            = "https://accounts.livechat.com/v2/token"
	userURL             = "https://accounts.livechat.com/v2/accounts/me"
	defaultProviderName = "livechat"
)

// Account represents LiveChat account
type Account struct {
	ID             string `json:"account_id"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	Link           string `json:"link"`
	EmailVerified  bool   `json:"email_verified"`
	AvatarURL      string `json:"avatar_url"`
	OrganizationID string `json:"organization_id"`
}

type RawUserData struct {
	Region         string `json:"region"`
	OrganizationID string `json:"organization_id"`
}

// Provider is the implementation of `goth.Provider` for accessing Livechat
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	HTTPClient  *http.Client

	config       *oauth2.Config
	providerName string

	consent bool
}

type Option func(p *Provider)

func WithConsent() Option {
	return func(p *Provider) {
		p.consent = true
	}
}

// New creates the new Livechat provider
func New(clientKey, secret, callbackURL string, opts ...Option) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: defaultProviderName,
	}
	p.config = newConfig(p)

	for _, o := range opts {
		o(p)
	}
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

// Debug is a no-op for the livechat package
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Livechat for an authentication end-point
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	var opts []oauth2.AuthCodeOption

	if p.consent {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "consent"))
	}

	url := p.config.AuthCodeURL(state, opts...)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will fetch basic information about Livechat user
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		RefreshToken: s.RefreshToken,
		Provider:     p.Name(),
		ExpiresAt:    s.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	account, err := FetchAccount(p.Client(), s.AccessToken)
	if err != nil {
		return user, err
	}
	setGothUser(account, &user)

	parts := strings.Split(s.AccessToken, ":")
	if len(parts) != 2 {
		return user, errors.New("invalid_region")
	}

	var userDataMap map[string]interface{}
	{
		userData := &RawUserData{
			Region:         parts[0],
			OrganizationID: account.OrganizationID,
		}

		jUserData, _ := json.Marshal(userData)
		json.Unmarshal(jUserData, &userDataMap)
	}

	user.RawData = userDataMap

	return user, err
}

func FetchAccount(c *http.Client, accessToken string) (*Account, error) {
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var account *Account

	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		return nil, err
	}

	return account, nil
}

func setGothUser(a *Account, user *goth.User)  {
	user.UserID = a.ID
	user.Name = a.Name
	user.FirstName, user.LastName = splitName(a.Name)
	user.Email = a.Email
	user.AvatarURL = a.AvatarURL
}

func splitName(name string) (string, string) {
	nameSplit := strings.SplitN(name, " ", 2)
	firstName := nameSplit[0]

	var lastName string
	if len(nameSplit) == 2 {
		lastName = nameSplit[1]
	}

	return firstName, lastName
}

func newConfig(provider *Provider) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		// The list of resources and actions is automatically created based on the scopes selected for your app in Developer Console
		Scopes: []string{},
	}

	return c
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(context.Background(), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}
