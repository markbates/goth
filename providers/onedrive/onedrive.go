// Package onedrive implements the OAuth2 protocol for authenticating users through onedrive.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package onedrive

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://login.live.com/oauth20_authorize.srf"
	tokenURL        string = "https://login.live.com/oauth20_token.srf"
	endpointProfile string = "https://graph.microsoft.com/v1.0/me"
)

// Provider is the implementation of `goth.Provider` for accessing Onedrive.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new Onedrive provider and sets up important connection details.
// You should always call `onedrive.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "onedrive",
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

// Debug is a no-op for the onedrive package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Onedrive for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Microsoft Graph API and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)

	resp, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return user, fmt.Errorf("%s responded with %d: %s", p.providerName, resp.StatusCode, string(body))
	}

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return user, err
	}

	user.RawData = raw
	user.UserID = raw["id"].(string)
	user.Email = raw["mail"].(string)
	if user.Email == "" {
		user.Email = raw["userPrincipalName"].(string) // Fallback if mail is missing
	}
	user.Name = raw["displayName"].(string)

	return user, nil
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
		c.Scopes = append(c.Scopes, "wl.signin", "wl.emails", "wl.offline_access")
	}

	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name  string            `json:"name"`
		Email map[string]string `json:"emails"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = u.Email["account"]
	user.Name = u.Name
	user.NickName = u.Name
	user.UserID = u.Email["account"] // onedrive doesn't provide separate user_id

	return nil
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
