// Package mailru implements the OAuth2 protocol for authenticating users through mailru.com.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package mailru

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL      = "https://connect.mail.ru/oauth/authorize"
	tokenURL     = "https://connect.mail.ru/oauth/token"
	endpointUser = "https://www.appsmail.ru/platform/api"
)

// New creates a new MAILRU provider and sets up important connection details.
// You should always call `mailru.New` to get a new provider. Never try to
// create one manually.
func New(clientID, clientSecret, redirectURL string, scopes ...string) *Provider {
	var c = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return &Provider{
		name:        "mailru",
		oauthConfig: c,
	}
}

// Provider is the implementation of `goth.Provider` for accessing Github.
type Provider struct {
	name         string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	oauthConfig  *oauth2.Config
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.name
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.name = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.httpClient)
}

// BeginAuth asks MAILRU for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.oauthConfig.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to MAILRU and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (_ goth.User, err error) {
	var (
		sess = session.(*Session)
		user = goth.User{
			AccessToken:  sess.AccessToken,
			RefreshToken: sess.RefreshToken,
			Provider:     p.Name(),
			ExpiresAt:    sess.ExpiresAt,
		}
	)

	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without access token", p.name)
	}

	var (
		sig = fmt.Sprintf(
			"app_id=%smethod=users.getInfosecure=1session_key=%s%s",
			p.oauthConfig.ClientID, sess.AccessToken, p.oauthConfig.ClientSecret,
		)
		hasher = md5.New()
	)

	if _, err = io.WriteString(hasher, sig); err != nil {
		return user, err
	}

	var reqURL = fmt.Sprintf(
		"%s?app_id=%s&method=users.getInfo&secure=1&session_key=%s&sig=%x",
		endpointUser, p.oauthConfig.ClientID, sess.AccessToken, hasher.Sum(nil),
	)

	res, err := p.Client().Get(reqURL)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.name, res.StatusCode)
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return user, err
	}

	var raw []json.RawMessage
	if err = json.Unmarshal(buf, &raw); err != nil {
		return user, err
	}

	if len(raw) == 0 {
		return user, fmt.Errorf("%s cannot get user information", p.name)
	}

	if err = json.Unmarshal(raw[0], &user.RawData); err != nil {
		return user, err
	}

	// extract and ignore all errors
	user.UserID, _ = user.RawData["uid"].(string)
	user.FirstName, _ = user.RawData["first_name"].(string)
	user.LastName, _ = user.RawData["last_name"].(string)
	user.NickName, _ = user.RawData["nick"].(string)
	user.Email, _ = user.RawData["email"].(string)
	user.AvatarURL, _ = user.RawData["pic_big"].(string)

	return user, err
}

// Debug is a no-op for the mailru package.
func (p *Provider) Debug(debug bool) {}

// RefreshToken refresh token is not provided by mailru.
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	t := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.oauthConfig.TokenSource(goth.ContextForClient(p.Client()), t)

	return ts.Token()
}

// RefreshTokenAvailable refresh token is not provided by mailru
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}
