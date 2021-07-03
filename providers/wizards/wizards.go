// Package wizards implements the OAuth2 protocol for authenticating users through Wizards of the Coast "Platform".
// This package can be used as a reference implementation of an OAuth2 provider for Wizards.
package wizards

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL      string = "https://myaccounts.wizards.com/authorize"
	tokenURL     string = "https://api.platform.wizards.com/auth/oauth/token"
	userEndpoint string = "https://api.platform.wizards.com/profile"
)

const (
	// ScopeEmail requests access to the users email.
	ScopeEmail = "email"
)

// New creates a new Wizards provider, and sets up important connection details.
// You should always call `wizards.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey string, secret string, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "wizards",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Wizards.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Name gets the name used to retrieve this provider.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client ...
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is no-op for the Wizards package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Wizards for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state, oauth2.SetAuthURLParam("version", "2"))
	s := &Session{
		AuthURL: url,
	}
	return s, nil
}

// FetchUser will go to Wizards and access basic info about the user.
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

	req, err := http.NewRequest("GET", userEndpoint, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	req.Header.Set("Client-ID", p.config.ClientID)
	resp, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	err = userFromReader(resp.Body, &user)
	return user, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		AccountID       string `json:"accountID"`
		CCPAPRotectData bool   `json:"ccpaProtectData"`
		CountryCode     string `json:"countryCode"`
		CreatedAt       string `json:"createdAt"`
		DataOptIn       bool   `json:"dataOptIn"`
		DisplayName     string `json:"displayName"`
		Email           string `json:"email"`
		EmailOptIn      bool   `json:"emailOptIn"`
		EmailVerified   bool   `json:"emailVerified"`
		ExternalID      string `json:"externalID"`
		FirstName       string `json:"firstName"`
		LastName        string `json:"lastName"`
		PersonaID       string `json:"personaID"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	if len(u.AccountID) == 0 {
		return fmt.Errorf("user not found in response")
	}

	user.Name = u.FirstName + u.LastName
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.Email = u.Email
	user.NickName = u.DisplayName
	user.Location = u.CountryCode
	user.UserID = u.AccountID

	return nil
}

func newConfig(p *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RedirectURL:  p.CallbackURL,
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
		c.Scopes = []string{ScopeEmail}
	}

	return c
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
