// Package gitee implements the OAuth2 protocol for authenticating users through Gitee.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package gitee

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const providerName = "gitee"

var (
	AuthURL    = "https://gitee.com/oauth/authorize"
	TokenURL   = "https://gitee.com/oauth/token"
	ProfileURL = "https://gitee.com/api/v5/user"
	EmailURL   = "https://gitee.com/api/v5/emails"
)

var ErrNoPrimaryEmail = errors.New("The user does not have a primary email on Gitee")

type Provider struct {
	Key          string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	profileURL   string
	emailURL     string
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

// Debug is a no-op for the package.
func (p *Provider) Debug(debug bool) {
	// todo:for debug log?
}

// BeginAuth asks Gitee for an authentication endpoint.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	authURL := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: authURL,
	}
	return session, nil
}

func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	user := goth.User{
		Provider: p.Name(),
	}

	sess, ok := session.(*Session)
	if !ok {
		return user, errors.New("invalid session assert")
	}
	if sess.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}
	user.AccessToken = sess.AccessToken

	req, err := http.NewRequest(http.MethodGet, p.profileURL, nil)
	if err != nil {
		return user, nil
	}

	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	rsp, err := p.Client().Do(req)
	if err != nil {
		return user, nil
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("gitee API responded with a %d trying to fetch user information", rsp.StatusCode)
	}

	err = parseUserFromBody(rsp.Body, &user)
	if err != nil {
		return user, err
	}

	if user.Email == "" {
		for _, scope := range p.config.Scopes {
			if strings.TrimSpace(scope) == "user" || strings.TrimSpace(scope) == "emails" {
				user.Email, err = getPrivateMail(p, sess)
				if err != nil {
					return user, err
				}
				break
			}
		}
	}

	return user, nil
}

func parseUserFromBody(r io.Reader, user *goth.User) error {
	err := json.NewDecoder(r).Decode(&user.RawData)
	if err != nil {
		fmt.Printf("x2:%+v", err)
		return err
	}

	if login, ok := user.RawData["login"].(string); ok {
		user.Name = login
	}
	if name, ok := user.RawData["name"].(string); ok {
		user.NickName = name
	}
	if email, ok := user.RawData["email"].(string); ok {
		user.Email = email
	}
	if bio, ok := user.RawData["bio"].(string); ok {
		user.Description = bio
	}
	if avatarURL, ok := user.RawData["avatar_url"].(string); ok {
		user.AvatarURL = avatarURL
	}

	return nil
}

type emails []struct {
	Email string   `json:"email"`
	State string   `json:"state"`
	Scope []string `json:"scope"`
}

func getPrivateMail(p *Provider, sess *Session) (email string, err error) {
	req, err := http.NewRequest(http.MethodGet, p.emailURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)

	rsp, err := p.Client().Do(req)
	if err != nil {
		return "", err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gitee API responded with a %d trying to get user email", rsp.StatusCode)
	}

	var emails emails
	err = json.NewDecoder(rsp.Body).Decode(&emails)
	if err != nil {
		return "", err
	}

	for _, email := range emails {
		for _, scope := range email.Scope {
			if scope == "primary" {
				return email.Email, nil
			}
		}
	}

	return "", ErrNoPrimaryEmail
}

// RefreshToken refresh token is provided by Gitee
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("todo: Refresh token is not provided by Gitee")
}

func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

func New(key, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(key, secret, callbackURL, AuthURL, TokenURL, ProfileURL, EmailURL, scopes...)
}

func NewCustomisedURL(key, secret, callbackURL, authURL, tokenURL, profileURL, emailURL string, scopes ...string) *Provider {
	p := &Provider{
		Key:          key,
		Secret:       secret,
		CallbackURL:  callbackURL,
		HTTPClient:   &http.Client{},
		config:       &oauth2.Config{},
		providerName: providerName,
		profileURL:   ProfileURL,
		emailURL:     EmailURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.Key,
		ClientSecret: provider.Secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		RedirectURL: provider.CallbackURL,
		Scopes:      []string{},
	}

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
}
