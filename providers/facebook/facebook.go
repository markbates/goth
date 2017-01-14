// Package facebook implements the OAuth2 protocol for authenticating users through Facebook.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package facebook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://www.facebook.com/dialog/oauth"
	tokenURL        string = "https://graph.facebook.com/oauth/access_token"
	endpointProfile string = "https://graph.facebook.com/me?fields=email,first_name,last_name,link,about,id,name,picture,location"
)

// New creates a new Facebook provider, and sets up important connection details.
// You should always call `facebook.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:   clientKey,
		Secret:      secret,
		CallbackURL: callbackURL,
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Facebook.
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	config      *oauth2.Config
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "facebook"
}

// Debug is a no-op for the facebook package.
func (p *Provider) Debug(debug bool) {}

func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return p.BeginAuthCtx(context.TODO(), state)
}

// BeginAuthCtx asks Facebook for an authentication end-point.
func (p *Provider) BeginAuthCtx(ctx context.Context, state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	return p.FetchUserCtx(context.TODO(), session)
}

// FetchUserCtx will go to Facebook and access basic information about the user.
func (p *Provider) FetchUserCtx(ctx context.Context, session goth.Session) (
	goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
		ExpiresAt:   sess.ExpiresAt,
	}

	client, err := goth.HTTPClient(ctx)
	if err != nil {
		return user, err
	}

	response, err := client.Get(endpointProfile + "&access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		return user, err
	}
	defer response.Body.Close()

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

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		About     string `json:"about"`
		Name      string `json:"name"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Link      string `json:"link"`
		Picture   struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
		Location struct {
			Name string `json:"name"`
		} `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.NickName = u.Name
	user.Email = u.Email
	user.Description = u.About
	user.AvatarURL = u.Picture.Data.URL
	user.UserID = u.ID
	user.Location = u.Location.Name

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

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return p.RefreshTokenCtx(context.TODO(), refreshToken)
}

// RefreshTokenCtx refresh token is not provided by facebook
func (p *Provider) RefreshTokenCtx(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by facebook")
}

// RefreshTokenAvailable refresh token is not provided by facebook
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
