// Package salesforce implements the OAuth2 protocol for authenticating users through salesforce.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package salesforce

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// These vars define the Authentication and Token URLS for Salesforce. If
// using Salesforce Community, you should change these values before calling New.
//
// Examples:
//
//	salesforce.AuthURL = "https://salesforce.acme.com/services/oauth2/authorize
//	salesforce.TokenURL = "https://salesforce.acme.com/services/oauth2/token
var (
	AuthURL  = "https://login.salesforce.com/services/oauth2/authorize"
	TokenURL = "https://login.salesforce.com/services/oauth2/token"

	// endpointProfile    string = "https://api.salesforce.com/2.0/users/me"
)

// Provider is the implementation of `goth.Provider` for accessing Salesforce.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new Salesforce provider and sets up important connection details.
// You should always call `salesforce.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "salesforce",
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

// Debug is a no-op for the salesforce package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Salesforce for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Salesforce and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	url, err := url.Parse(s.ID)
	if err != nil {
		return user, err
	}

	// creating dynamic url to retrieve user information
	userURL := url.Scheme + "://" + url.Host + "/" + url.Path
	req, err := http.NewRequest("GET", userURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
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

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  AuthURL,
			TokenURL: TokenURL,
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
	var rawData map[string]interface{}

	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	if err != nil {
		return err
	}

	err = json.Unmarshal(buf.Bytes(), &rawData)
	if err != nil {
		return err
	}

	u := struct {
		Name      string `json:"display_name"`
		NickName  string `json:"nick_name"`
		Location  string `json:"addr_country"`
		Email     string `json:"email"`
		AvatarURL string `json:"photos.picture"`
		ID        string `json:"user_id"`
	}{}

	err = json.Unmarshal(buf.Bytes(), &u)
	if err != nil {
		return err
	}
	user.Email = u.Email
	user.Name = u.Name
	user.NickName = u.Name
	user.UserID = u.ID
	user.Location = u.Location
	user.RawData = rawData

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

func (p *Provider) FetchUserWithToken(token string) (goth.User, error) {
	return goth.User{}, errors.New("not implemented")
}
