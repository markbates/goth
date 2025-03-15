// Package vk implements the OAuth2 protocol for authenticating users through vk.com.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package vk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

var (
	authURL      = "https://oauth.vk.com/authorize"
	tokenURL     = "https://oauth.vk.com/access_token"
	endpointUser = "https://api.vk.com/method/users.get"
	apiVersion   = "5.131"
)

// New creates a new VK provider and sets up important connection details.
// You should always call `vk.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "vk",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing VK.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	version      string
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

// BeginAuth asks VK for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}

	return session, nil
}

// FetchUser will go to VK and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
		ExpiresAt:   sess.ExpiresAt,
		Email:       sess.email,
	}

	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	fields := "photo_200,nickname"
	requestURL := fmt.Sprintf("%s?fields=%s&access_token=%s&v=%s", endpointUser, fields, sess.AccessToken, apiVersion)
	response, err := p.Client().Get(requestURL)
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := io.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	response := struct {
		Response []struct {
			ID        int64  `json:"id"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			NickName  string `json:"nickname"`
			Photo200  string `json:"photo_200"`
		} `json:"response"`
	}{}

	err := json.NewDecoder(reader).Decode(&response)
	if err != nil {
		return err
	}

	if len(response.Response) == 0 {
		return fmt.Errorf("vk cannot get user information")
	}

	u := response.Response[0]

	user.UserID = strconv.FormatInt(u.ID, 10)
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.NickName = u.NickName
	user.AvatarURL = u.Photo200

	return err
}

// Debug is a no-op for the vk package.
func (p *Provider) Debug(debug bool) {}

// RefreshToken refresh token is not provided by vk
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by vk")
}

// RefreshTokenAvailable refresh token is not provided by vk
func (p *Provider) RefreshTokenAvailable() bool {
	return false
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
		Scopes: []string{
			"email",
		},
	}

	defaultScopes := map[string]struct{}{
		"email": {},
	}

	for _, scope := range scopes {
		if _, exists := defaultScopes[scope]; !exists {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}
