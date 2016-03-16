package instagram

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
)

var (
	authURL         = "https://api.instagram.com/oauth/authorize/"
	tokenURL        = "https://api.instagram.com/oauth/access_token"
	endpointProfile = "https://api.instagram.com/v1/users/self/"
)

// New creates a new Instagram provider, and sets up important connection details.
// You should always call `instagram.New` to get a new Provider. Never try to craete
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

// Provider is the implementation of `goth.Provider` for accessing Instagram
type Provider struct {
	ClientKey   string
	Secret      string
	CallbackURL string
	UserAgent   string
	config      *oauth2.Config
}

// Name is the name used to retrive this provider later.
func (p *Provider) Name() string {
	return "instagram"
}

//Debug TODO
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Instagram for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Instagram and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}

	response, err := http.Get(endpointProfile + "?access_token=" + url.QueryEscape(sess.AccessToken))
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
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
		Data struct {
			ID             string `json:"id"`
			UserName       string `json:"username"`
			FullName       string `json:"full_name"`
			ProfilePicture string `json:"profile_picture"`
			Bio            string `json:"bio"`
			Website        string `json:"website"`
			Counts         struct {
				Media      int `json:"media"`
				Follows    int `json:"follows"`
				FollowedBy int `json:"followed_by"`
			} `json:"counts"`
		} `json:"data"`
	}{}
	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}
	user.Name = u.Data.UserName
	user.NickName = u.Data.UserName
	user.AvatarURL = u.Data.ProfilePicture
	user.Description = u.Data.Bio
	return err
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
		Scopes: []string{
			"basic",
		},
	}
	defaultScopes := map[string]struct{}{
		"basic": {},
	}

	for _, scope := range scopes {
		if _, exists := defaultScopes[scope]; !exists {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}

//RefreshToken refresh token is not provided by instagram
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by instagram")
}

//RefreshTokenAvailable refresh token is not provided by instagram
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
