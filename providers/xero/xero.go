// Package xero implements the OAuth protocol for authenticating users through Xero.
package xero

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"

	"github.com/markbates/goth"
	"github.com/mrjones/oauth"
)

// Organisation is the expected response from the Organisation endpoint - this is not a complete schema
type Organisation struct {
	// Display name of organisation shown in Xero
	Name string `json:"Name,omitempty"`

	// Organisation name shown on Reports
	LegalName string `json:"LegalName,omitempty"`

	// Organisation Type
	OrganisationType string `json:"OrganisationType,omitempty"`

	// Country code for organisation. See ISO 3166-2 Country Codes
	CountryCode string `json:"CountryCode,omitempty"`

	// A unique identifier for the organisation. Potential uses.
	ShortCode string `json:"ShortCode,omitempty"`
}

// APIResponse is the Total response from the Xero API
type APIResponse struct {
	Organisations []Organisation `json:"Organisations,omitempty"`
}

var (
	requestURL      = "https://api.xero.com/oauth/RequestToken"
	authorizeURL    = "https://api.xero.com/oauth/Authorize"
	tokenURL        = "https://api.xero.com/oauth/AccessToken"
	endpointProfile = "https://api.xero.com/api.xro/2.0/"
	// userAgentString should be changed to match the name of your Application
	userAgentString    = os.Getenv("XERO_USER_AGENT") + " (goth-xero 1.0)"
	privateKeyFilePath = os.Getenv("XERO_PRIVATE_KEY_PATH")
)

// New creates a new Xero provider, and sets up important connection details.
// You should always call `xero.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
		// Method determines how you will connect to Xero.
		// Options are public, private, and partner
		// Use public if this is your first time.
		// More details here: https://developer.xero.com/documentation/getting-started/api-application-types
		Method:       os.Getenv("XERO_METHOD"),
		providerName: "xero",
	}

	switch p.Method {
	case "private":
		p.consumer = newPrivateOrPartnerConsumer(p, authorizeURL)
	case "public":
		p.consumer = newPublicConsumer(p, authorizeURL)
	case "partner":
		p.consumer = newPrivateOrPartnerConsumer(p, authorizeURL)
	default:
		p.consumer = newPublicConsumer(p, authorizeURL)
	}
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Xero.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	Method       string
	debug        bool
	consumer     *oauth.Consumer
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

// Client does pretty much everything
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug sets the logging of the OAuth client to verbose.
func (p *Provider) Debug(debug bool) {
	p.debug = debug
}

// BeginAuth asks Xero for an authentication end-point and a request token for a session.
// Xero does not support the "state" variable.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	requestToken, url, err := p.consumer.GetRequestTokenAndUrl(p.CallbackURL)
	if err != nil {
		return nil, err
	}
	session := &Session{
		AuthURL:      url,
		RequestToken: requestToken,
	}
	return session, err
}

// FetchUser will go to Xero and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		Provider: p.Name(),
	}

	if sess.AccessToken == nil {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	response, err := p.consumer.Get(
		endpointProfile+"Organisation",
		nil,
		sess.AccessToken)

	if err != nil {
		return user, err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	var apiResponse APIResponse
	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return user, fmt.Errorf("Could not read response: %s", err.Error())
	}
	if responseBytes == nil {
		return user, fmt.Errorf("Received no response: %s", err.Error())
	}
	err = json.Unmarshal(responseBytes, &apiResponse)
	if err != nil {
		return user, fmt.Errorf("Could not unmarshal response: %s", err.Error())
	}

	user.Name = apiResponse.Organisations[0].Name
	user.NickName = apiResponse.Organisations[0].LegalName
	user.Location = apiResponse.Organisations[0].CountryCode
	user.Description = apiResponse.Organisations[0].OrganisationType
	user.UserID = apiResponse.Organisations[0].ShortCode

	user.AccessToken = sess.AccessToken.Token
	user.AccessTokenSecret = sess.AccessToken.Secret
	user.ExpiresAt = sess.AccessTokenExpires
	return user, err
}

// newPublicConsumer creates a consumer capable of communicating with a Public application: https://developer.xero.com/documentation/auth-and-limits/public-applications
func newPublicConsumer(provider *Provider, authURL string) *oauth.Consumer {
	c := oauth.NewConsumer(
		provider.ClientKey,
		provider.Secret,
		oauth.ServiceProvider{
			RequestTokenUrl:   requestURL,
			AuthorizeTokenUrl: authURL,
			AccessTokenUrl:    tokenURL},
	)

	c.Debug(provider.debug)

	accepttype := []string{"application/json"}
	useragent := []string{userAgentString}
	c.AdditionalHeaders = map[string][]string{
		"Accept":     accepttype,
		"User-Agent": useragent,
	}

	return c
}

// newPartnerConsumer creates a consumer capable of communicating with a Partner application: https://developer.xero.com/documentation/auth-and-limits/partner-applications
func newPrivateOrPartnerConsumer(provider *Provider, authURL string) *oauth.Consumer {
	privateKeyFileContents, err := os.ReadFile(privateKeyFilePath)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(privateKeyFileContents)

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	c := oauth.NewRSAConsumer(
		provider.ClientKey,
		privateKey,
		oauth.ServiceProvider{
			RequestTokenUrl:   requestURL,
			AuthorizeTokenUrl: authURL,
			AccessTokenUrl:    tokenURL},
	)

	c.Debug(provider.debug)

	accepttype := []string{"application/json"}
	useragent := []string{userAgentString}
	c.AdditionalHeaders = map[string][]string{
		"Accept":     accepttype,
		"User-Agent": useragent,
	}

	return c
}

// RefreshOAuth1Token should be used instead of RefeshToken which is not compliant with the Oauth1.0a standard
func (p *Provider) RefreshOAuth1Token(session *Session) error {
	newAccessToken, err := p.consumer.RefreshToken(session.AccessToken)
	if err != nil {
		return err
	}
	session.AccessToken = newAccessToken
	session.AccessTokenExpires = time.Now().UTC().Add(30 * time.Minute)
	return nil
}

// RefreshToken refresh token is not provided by the Xero Public or Private Application -
// only the Partner Application and you must use RefreshOAuth1Token instead
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is only provided by Xero for Partner Applications")
}

// RefreshTokenAvailable refresh token is not provided by the Xero Public or Private Application -
// only the Partner Application and you must use RefreshOAuth1Token instead
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
