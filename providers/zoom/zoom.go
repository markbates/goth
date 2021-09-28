// Package zoom implements the OAuth2 protocol for authenticating users through zoo.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package zoom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"net/http"
)

var (
	authorizeURL string = "https://zoom.us/oauth/authorize"
	tokenURL     string = "https://zoom.us/oauth/token"
	profileURL   string = "https://zoom.us/v2/users/me"
)

// Provider is the implementation of `goth.Provider` for accessing Zoom.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

type profileResp struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	AvatarURL string `json:"pic_url"`
	ID        string `json:"id"`
}

// New creates a new Zoom provider and sets up connection details.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "zoom",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve the provider.
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

// Debug is a no-op for the zoom package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth returns zoom authentication endpoint.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser makes a request to profileURL and returns zoom user data.
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

	req, err := http.NewRequest("GET", profileURL, nil)
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

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authorizeURL,
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

	u := &profileResp{}
	err = json.Unmarshal(buf.Bytes(), &u)
	if err != nil {
		return err
	}

	user.Email = u.Email
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.Name = fmt.Sprintf("%s %s", u.FirstName, u.LastName)
	user.UserID = u.ID
	user.AvatarURL = u.AvatarURL
	user.RawData = rawData

	return nil
}
