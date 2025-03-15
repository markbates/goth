// Package kakao implements the OAuth2 protocol for authenticating users through kakao.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package kakao

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL      string = "https://kauth.kakao.com/oauth/authorize"
	tokenURL     string = "https://kauth.kakao.com/oauth/token"
	endpointUser string = "https://kapi.kakao.com/v2/user/me"
)

// Provider is the implementation of `goth.Provider` for accessing Kakao.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

// New creates a new Kakao provider and sets up important connection details.
// You should always call `kakao.New` to get a new provider.  Never try to
// create one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "kakao",
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

// Client returns a pointer to http.Client setting some client fallback.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the kakao package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks kakao for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to kakao and access basic information about the user.
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

	// Get the userID, kakao needs userID in order to get user profile info
	c := p.Client()
	req, err := http.NewRequest("GET", endpointUser, nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", "Bearer "+sess.AccessToken)

	response, err := c.Do(req)
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := io.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	u := struct {
		ID         int `json:"id"`
		Properties struct {
			Nickname       string `json:"nickname"`
			ThumbnailImage string `json:"thumbnail_image"`
			ProfileImage   string `json:"profile_image"`
		} `json:"properties"`
	}{}

	if err = json.NewDecoder(bytes.NewReader(bits)).Decode(&u); err != nil {
		return user, err
	}

	id := strconv.Itoa(u.ID)

	user.NickName = u.Properties.Nickname
	user.AvatarURL = u.Properties.ProfileImage
	user.UserID = id
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

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}
