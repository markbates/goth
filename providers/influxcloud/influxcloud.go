// Package influxdata implements the OAuth2 protocol for authenticating users through InfluxCloud.
// It is based off of the github implementation.
package influxcloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	// The hard coded domain is difficult here because influx cloud has an acceptance
	// domain that is different and we will need that for enterprise development.
	defaultDomain string = "cloud.influxdata.com"
	userAPIPath   string = "/api/v1/user"
	domainEnvKey  string = "INFLUXCLOUD_OAUTH_DOMAIN"
	authPath      string = "/oauth/authorize"
	tokenPath     string = "/oauth/token"
)

// New creates a new influx provider, and sets up important connection details.
// You should always call `influxcloud.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	domain := os.Getenv(domainEnvKey)
	if domain == "" {
		domain = defaultDomain
	}
	tokenURL := fmt.Sprintf("https://%s%s", domain, tokenPath)
	authURL := fmt.Sprintf("https://%s%s", domain, authPath)
	userAPIEndpoint := fmt.Sprintf("https://%s%s", domain, userAPIPath)

	p := &Provider{
		ClientKey:       clientKey,
		Secret:          secret,
		CallbackURL:     callbackURL,
		UserAPIEndpoint: userAPIEndpoint,
		Config: &oauth2.Config{
			ClientID:     clientKey,
			ClientSecret: secret,
			RedirectURL:  callbackURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
			Scopes: scopes,
		},
	}
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Influx.
type Provider struct {
	ClientKey       string
	Secret          string
	CallbackURL     string
	UserAPIEndpoint string
	Config          *oauth2.Config
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return "influxcloud"
}

// Debug is a no-op for the influxcloud package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Influx for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.Config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Influx and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}

	response, err := http.Get(p.UserAPIEndpoint + "?access_token=" + url.QueryEscape(sess.AccessToken))
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
		ID       int    `json:"id"`
		Email    string `json:"email"`
		Bio      string `json:"bio"`
		Name     string `json:"name"`
		Login    string `json:"login"`
		Picture  string `json:"avatar_url"`
		Location string `json:"location"`
	}{}

	err := json.NewDecoder(reader).Decode(&u)
	if err != nil {
		return err
	}

	user.Name = u.Name
	user.NickName = u.Login
	user.Email = u.Email
	user.Description = u.Bio
	user.AvatarURL = u.Picture
	user.UserID = strconv.Itoa(u.ID)
	user.Location = u.Location

	return err
}

//RefreshToken refresh token is not provided by influxcloud
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by influxcloud")
}

//RefreshTokenAvailable refresh token is not provided by influxcloud
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
