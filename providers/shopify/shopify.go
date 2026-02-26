// Package shopify implements the OAuth2 protocol for authenticating users through Shopify.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package shopify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	providerName = "shopify"

	// URL protocol and subdomain will be populated by newConfig().
	authURL         = "myshopify.com/admin/oauth/authorize"
	tokenURL        = "myshopify.com/admin/oauth/access_token"
	endpointProfile = "myshopify.com/admin/api/2019-04/shop.json"
)

// Provider is the implementation of `goth.Provider` for accessing Shopify.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	shopName     string
	scopes       []string
}

// New creates a new Shopify provider and sets up important connection details.
// You should always call `shopify.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: providerName,
		scopes:       scopes,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Client is HTTP client to be used in all fetch operations.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// SetShopName is to update the shopify shop name, needed when interfacing with different shops.
func (p *Provider) SetShopName(name string) {
	p.shopName = name

	// Reparse config with the new shop name.
	p.config = newConfig(p, p.scopes)
}

// Debug is a no-op for the Shopify package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Shopify for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by Shopify")
}

// FetchUser will go to Shopify and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	shop := goth.User{
		AccessToken: s.AccessToken,
		Provider:    p.Name(),
	}

	if shop.AccessToken == "" {
		// Data is not yet retrieved since accessToken is still empty.
		return shop, fmt.Errorf("%s cannot get shop information without accessToken", p.providerName)
	}

	// Build the request.
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s.%s", p.shopName, endpointProfile), nil)
	if err != nil {
		return shop, err
	}
	req.Header.Set("X-Shopify-Access-Token", s.AccessToken)

	// Execute the request.
	resp, err := p.Client().Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return shop, err
	}
	defer resp.Body.Close()

	// Check our response status.
	if resp.StatusCode != http.StatusOK {
		return shop, fmt.Errorf("%s responded with a %d trying to fetch shop information", p.providerName, resp.StatusCode)
	}

	// Parse response.
	return shop, shopFromReader(resp.Body, &shop)
}

func shopFromReader(r io.Reader, shop *goth.User) error {
	rsp := struct {
		Shop struct {
			ID              int64  `json:"id"`
			Name            string `json:"name"`
			Email           string `json:"email"`
			City            string `json:"city"`
			Country         string `json:"country"`
			ShopOwner       string `json:"shop_owner"`
			MyShopifyDomain string `json:"myshopify_domain"`
			PlanDisplayName string `json:"plan_display_name"`
		} `json:"shop"`
	}{}

	err := json.NewDecoder(r).Decode(&rsp)
	if err != nil {
		return err
	}

	shop.UserID = strconv.Itoa(int(rsp.Shop.ID))
	shop.Name = rsp.Shop.Name
	shop.Email = rsp.Shop.Email
	shop.Description = fmt.Sprintf("%s (%s)", rsp.Shop.MyShopifyDomain, rsp.Shop.PlanDisplayName)
	shop.Location = fmt.Sprintf("%s, %s", rsp.Shop.City, rsp.Shop.Country)
	shop.AvatarURL = "Not provided by the Shopify API"
	shop.NickName = "Not provided by the Shopify API"

	return nil
}

func newConfig(p *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RedirectURL:  p.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("https://%s.%s", p.shopName, authURL),
			TokenURL: fmt.Sprintf("https://%s.%s", p.shopName, tokenURL),
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for i, scope := range scopes {
			// Shopify require comma separated scopes.
			s := fmt.Sprintf("%s,", scope)
			if i == len(scopes)+1 {
				s = scope
			}
			c.Scopes = append(c.Scopes, s)
		}
	} else {
		// Default to a read customers scope.
		c.Scopes = append(c.Scopes, ScopeReadCustomers)
	}

	return c
}
