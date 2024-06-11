// Package okta implements the OAuth2 protocol for authenticating users through okta.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package okta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// Provider is the implementation of `goth.Provider` for accessing okta.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	issuerURL    string
	profileURL   string
}

// New creates a new Okta provider and sets up important connection details.
// You should always call `okta.New` to get a new provider.  Never try to
// create one manually.
func New(clientID, secret, orgURL, callbackURL string, scopes ...string) *Provider {
	issuerURL := orgURL + "/oauth2/default"
	authURL := issuerURL + "/v1/authorize"
	tokenURL := issuerURL + "/v1/token"
	profileURL := issuerURL + "/v1/userinfo"
	return NewCustomisedURL(clientID, secret, callbackURL, authURL, tokenURL, issuerURL, profileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientID, secret, callbackURL, authURL, tokenURL, issuerURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientID,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "okta",
		issuerURL:    issuerURL,
		profileURL:   profileURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
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

// Debug is a no-op for the okta package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks okta for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to okta and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
		UserID:       sess.UserID,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	response, err := p.Client().Do(req)
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

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Name       string `json:"name"`
		Email      string `json:"email"`
		FirstName  string `json:"given_name"`
		LastName   string `json:"family_name"`
		NickName   string `json:"nickname"`
		ID         string `json:"sub"`
		Locale     string `json:"locale"`
		ProfileURL string `json:"profile"`
		Username   string `json:"preferred_username"`
		Zoneinfo   string `json:"zoneinfo"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	rd := make(map[string]interface{})
	rd["ProfileURL"] = u.ProfileURL
	rd["Locale"] = u.Locale
	rd["Username"] = u.Username
	rd["Zoneinfo"] = u.Zoneinfo

	user.UserID = u.ID
	user.Email = u.Email
	user.Name = u.Name
	user.NickName = u.NickName
	user.FirstName = u.FirstName
	user.LastName = u.LastName

	user.RawData = rd

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
