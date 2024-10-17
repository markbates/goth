// Package azure implements the OAuth2 protocol for authenticating users through Azure.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package azuredevops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// These vars define the Authentication, Token, and API URLS for Azure. If
// using Azure enterprise you should change these values before calling New.
var (
	authURL    = "https://app.vssps.visualstudio.com/oauth2/authorize"
	tokenURL   = "https://app.vssps.visualstudio.com/oauth2/token"
	profileURL = "https://app.vssps.visualstudio.com/_apis/profile/profiles/me"
)

// New creates a new Azure provider, and sets up important connection details.
// You should always call `azure.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "azuredevops",
		profileURL:   profileURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Azure.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	profileURL   string
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

// Debug is a no-op for the azure package.
func (p *Provider) Debug(_ bool) {}

// BeginAuth asks Azure for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	urlStr := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: urlStr,
	}
	return session, nil
}

// FetchUser will go to Azure and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
		Provider:     p.Name(),
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", "Bearer "+sess.AccessToken)
	response, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("Azure Devops API responded with a %d trying to fetch user information", response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	if err != nil {
		return user, err
	}

	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID    string `json:"id"`
		Email string `json:"emailAddress"`
		Name  string `json:"displayName"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.Email = u.Email
	user.UserID = u.ID

	return err
}

func tokenFromReader(reader io.Reader, token *oauth2.Token) error {
	t := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    string `json:"expires_in"`
	}{}

	err := json.NewDecoder(reader).Decode(&t)
	if err != nil {
		return err
	}

	expiresIn, err := strconv.Atoi(t.ExpiresIn)
	if err != nil {
		return err
	}
	token.AccessToken = t.AccessToken
	token.RefreshToken = t.RefreshToken
	token.Expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return err
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

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	req, err := http.NewRequest("POST", p.config.Endpoint.TokenURL, nil)
	if err != nil {
		return token, err
	}

	form := url.Values{}
	form.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Add("client_assertion", p.Secret)
	form.Add("grant_type", "refresh_token")
	form.Add("assertion", refreshToken)
	form.Add("redirect_uri", p.config.RedirectURL)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Body = ioutil.NopCloser(strings.NewReader(form.Encode()))
	response, err := p.Client().Do(req)

	if err != nil {
		return token, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return token, fmt.Errorf("Azure Devops API responded with a %d trying to fetch user information", response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return token, err
	}

	err = tokenFromReader(bytes.NewReader(bits), token)
	if err != nil {
		return token, err
	}

	return token, err
}

func (p *Provider) RefreshTokenAvailable() bool {
	return true
}
