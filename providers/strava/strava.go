// Package strava implements the OAuth2 protocol for authenticating users through Strava.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package strava

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://www.strava.com/oauth/authorize"
	tokenURL        string = "https://www.strava.com/oauth/token"
	endpointProfile string = "https://www.strava.com/api/v3/athlete"
)

// New creates a new Strava provider, and sets up important connection details.
// You should always call `strava.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "strava",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Strava.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns an HTTP client to be used in all fetch operations.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the strava package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Strava for an authentication endpoint.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	authUrl := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: authUrl,
	}
	return session, nil
}

// FetchUser will go to Strava and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	reqUrl := fmt.Sprint(endpointProfile,
		"?access_token=", url.QueryEscape(sess.AccessToken),
	)
	response, err := p.Client().Get(reqUrl)
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
	u := struct {
		ID        int64  `json:"id"`
		Username  string `json:"username"`
		FirstName string `json:"firstname"`
		LastName  string `json:"lastname"`
		City      string `json:"city"`
		Region    string `json:"state"`
		Country   string `json:"country"`
		Gender    string `json:"sex"`
		Picture   string `json:"profile"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.UserID = fmt.Sprintf("%d", u.ID)
	user.Name = fmt.Sprintf("%s %s", u.FirstName, u.LastName)
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.NickName = u.Username
	user.AvatarURL = u.Picture
	user.Description = fmt.Sprintf(`{"gender":"%s"}`, u.Gender)
	user.Location = fmt.Sprintf(`{"city":"%s","region":"%s","country":"%s"}`, u.City, u.Region, u.Country)

	return err
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
		c.Scopes = []string{strings.Join(scopes, ",")}
	} else {
		c.Scopes = []string{"read"}
	}

	return c
}

// RefreshTokenAvailable refresh token is not provided by Strava
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken refresh token is not provided by Strava
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
