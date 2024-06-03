// Package jira implements the OAuth2 protocol for authenticating users through Jira.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package jira

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// These vars define the Authentication, Token, and API URLS for Jira. If
// using Jira enterprise you should change these values before calling New.
var (
	authURL     = "https://auth.atlassian.com/authorize"
	tokenURL    = "https://auth.atlassian.com/oauth/token"
	resourceURL = "https://api.atlassian.com/oauth/token/accessible-resources"
	profileURL  = "https://api.atlassian.com/ex/jira/%s/rest/api/2/myself"
)

// New creates a new Jira provider, and sets up important connection details.
// You should always call `jira.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, resourceURL, profileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, resourceURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "jira",
		resourceURL:  resourceURL,
		profileURL:   profileURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Jira.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	resourceURL  string
	profileURL   string
}

type getAccessibleResourcesResponse struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Scopes    []string `json:"scopes"`
	AvatarURL string   `json:"avatarUrl"`
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

// Debug is a no-op for the goth package.
func (p *Provider) Debug(_ bool) {}

// BeginAuth asks Goth for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

func (p *Provider) getAccessibleResources(accessToken string) ([]getAccessibleResourcesResponse, error) {
	req, err := http.NewRequest("GET", p.resourceURL, nil)
	if err != nil {
		return []getAccessibleResourcesResponse{}, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	r, err := p.Client().Do(req)
	if err != nil {
		return []getAccessibleResourcesResponse{}, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return []getAccessibleResourcesResponse{}, fmt.Errorf("jira responded with a %d trying to fetch accessible resources", r.StatusCode)
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return []getAccessibleResourcesResponse{}, err
	}

	var response []getAccessibleResourcesResponse

	err = json.Unmarshal(body, &response)

	if err != nil {
		return []getAccessibleResourcesResponse{}, err
	}
	return response, nil
}

// FetchUser will go to Jira and access basic information about the user.
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

	accessibleResources, err := p.getAccessibleResources(user.AccessToken)
	if err != nil {
		return user, err
	}
	if len(accessibleResources) == 0 {
		return user, fmt.Errorf("%s cannot get user information without any accessible resources", p.providerName)
	}

	req, err := http.NewRequest("GET", fmt.Sprintf(p.profileURL, accessibleResources[0].ID), nil)
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
		return user, fmt.Errorf("Jira responded with a %d trying to fetch user information", response.StatusCode)
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
		ID    string `json:"accountId"`
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
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

func (p *Provider) RefreshTokenAvailable() bool {
	return true
}
