// Package atlassian implements the OAuth2 protocol for authenticating users through atlassian.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package atlassian

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"fmt"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://auth.atlassian.com/authorize"
	tokenURL        string = "https://auth.atlassian.com/oauth/token"
	endpointProfile string = "https://api.atlassian.com/me"
)

// Provider is the implementation of `goth.Provider` for accessing Atlassian.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new Atlassian provider and sets up important connection details.
// You should always call `atlassian.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "atlassian",
	}
	p.config = newConfig(p, scopes)
	return p
}

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

// Debug is a no-op for the atlassian package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Atlassian for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	authUrl := p.config.AuthCodeURL(state)
	// audience and prompt are required static fields as described by
	// https://developer.atlassian.com/cloud/atlassian/platform/oauth-2-authorization-code-grants-3lo-for-apps/#authcode
	authUrl += "&audience=api.atlassian.com&prompt=consent"
	return &Session{
		AuthURL: authUrl,
	}, nil
}

// FetchUser will go to Atlassian and access basic information about the user.
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

	c := p.Client()
	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	response, err := c.Do(req)

	if err != nil {
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
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
	return user, err
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
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	} else {
		c.Scopes = append(c.Scopes, "read:me")
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {

	u := struct {
		Name            string `json:"name"`
		NickName        string `json:"nickname"`
		ExtendedProfile struct {
			Location string `json:"location"`
		} `json:"extended_profile"`
		Email     string `json:"email"`
		ID        string `json:"account_id"`
		AvatarURL string `json:"picture"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = u.Email
	user.Name = u.Name
	user.NickName = u.NickName
	user.UserID = u.ID
	user.Location = u.ExtendedProfile.Location
	user.AvatarURL = u.AvatarURL

	return err
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
