// Package reverb implements the OAuth2 protocol for authenticating users through Reverb.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package reverb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL       = "https://reverb.com/oauth/authorize"
	tokenURL      = "https://reverb.com/oauth/access_token"
	accountURL    = "https://reverb.com/api/my/account"
	providerName  = "reverb"
	versionHeader = "3.0"
)

// Provider is the implementation of `goth.Provider` for accessing Reverb.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new Reverb provider and sets up important connection details.
// You should always call `reverb.New` to get a new provider. Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: providerName,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type).
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client is the HTTP client used for all fetch operations.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the Reverb package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Reverb for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Reverb and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
		Provider:     p.Name(),
	}

	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	request, err := http.NewRequest(http.MethodGet, accountURL, nil)
	if err != nil {
		return user, err
	}

	request.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Version", versionHeader)

	response, err := p.Client().Do(request)
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

	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	if err := json.Unmarshal(payload, &user.RawData); err != nil {
		return user, err
	}

	var account accountResponse
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&account); err != nil {
		return user, err
	}

	user.Email = account.Email
	user.FirstName = account.FirstName
	user.LastName = account.LastName
	if fullName := strings.TrimSpace(strings.Join([]string{account.FirstName, account.LastName}, " ")); fullName != "" {
		user.Name = fullName
	}
	if account.ProfileSlug != "" {
		user.NickName = account.ProfileSlug
	}
	if account.UUID != "" {
		user.UserID = account.UUID
	} else if account.UserID != nil {
		user.UserID = account.UserID.String()
	}
	if account.Shop != nil {
		if account.Shop.Name != "" {
			user.Description = account.Shop.Name
		}
		if account.Shop.Slug != "" && user.NickName == "" {
			user.NickName = account.Shop.Slug
		}
	}
	if account.Links.Avatar.Href != "" {
		user.AvatarURL = account.Links.Avatar.Href
	}
	if account.ShippingRegionCode != "" {
		user.Location = account.ShippingRegionCode
	}

	return user, nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not.
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token.
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	return ts.Token()
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
		c.Scopes = append(c.Scopes, scopes...)
	}

	return c
}

type accountResponse struct {
	FirstName          string             `json:"first_name"`
	LastName           string             `json:"last_name"`
	Email              string             `json:"email"`
	ProfileSlug        string             `json:"profile_slug"`
	UUID               string             `json:"uuid"`
	UserID             *json.Number       `json:"user_id"`
	ShippingRegionCode string             `json:"shipping_region_code"`
	Shop               *shopPayload       `json:"shop"`
	Links              accountLinkPayload `json:"_links"`
}

type shopPayload struct {
	ID   *json.Number `json:"id"`
	Name string       `json:"name"`
	Slug string       `json:"slug"`
}

type accountLinkPayload struct {
	Avatar struct {
		Href string `json:"href"`
	} `json:"avatar"`
}
