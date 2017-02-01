// Package yahoo implements the OAuth2 protocol for authenticating users through yahoo.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package yahoo

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"fmt"
)

const (
	authURL         string = "https://api.login.yahoo.com/oauth2/request_auth"
	tokenURL        string = "https://api.login.yahoo.com/oauth2/get_token"
	endpointProfile string = "https://social.yahooapis.com/v1/user/GUID/profile?format=json"
)

// Provider is the implementation of `goth.Provider` for accessing Yahoo.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new Yahoo provider and sets up important connection details.
// You should always call `yahoo.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "yahoo",
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

// Debug is a no-op for the yahoo package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Yahoo for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to Yahoo and access basic information about the user.
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

	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	resp, err := p.Client().Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
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
		Profile struct {
			NickName string `json:"nickname"`
			Location string `json:"location"`
			ID       string `json:"guid"`
			Image struct {
				ImageURL string `json:"imageURL"`
			} `json:"image"`
		} `json:"profile"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	user.Email = "" //email is not provided by yahoo
	user.Name = u.Profile.NickName
	user.NickName = u.Profile.NickName
	user.UserID = u.Profile.ID
	user.Location = u.Profile.Location
	user.AvatarURL = u.Profile.Image.ImageURL
	return nil
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
