// Package bitbucket implements the OAuth2 protocol for authenticating users through Bitbucket.
package bitbucket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	authURL         string = "https://bitbucket.org/site/oauth2/authorize"
	tokenURL        string = "https://bitbucket.org/site/oauth2/access_token"
	endpointProfile string = "https://api.bitbucket.org/2.0/user"
	endpointEmail   string = "https://api.bitbucket.org/2.0/user/emails"
)

type EmailAddress struct {
	Type        string `json:"type"`
	Links       Links  `json:"links"`
	Email       string `json:"email"`
	IsPrimary   bool   `json:"is_primary"`
	IsConfirmed bool   `json:"is_confirmed"`
}

type Links struct {
	Self Self `json:"self"`
}

type Self struct {
	Href string `json:"href"`
}

type MailList struct {
	Values  []EmailAddress `json:"values"`
	Pagelen int            `json:"pagelen"`
	Size    int            `json:"size"`
	Page    int            `json:"page"`
}

// New creates a new Bitbucket provider, and sets up important connection details.
// You should always call `bitbucket.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "bitbucket",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing Bitbucket.
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

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the bitbucket package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Bitbucket for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to Bitbucket and access basic information about the user.
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

	if err := p.getUserInfo(&user, sess); err != nil {
		return user, err
	}

	if err := p.getEmail(&user, sess); err != nil {
		return user, err
	}

	return user, nil
}

func (p *Provider) getUserInfo(user *goth.User, sess *Session) error {
	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return err
	}
	authenticateRequest(req, sess)
	response, err := p.Client().Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return err
	}

	u := struct {
		ID    string `json:"uuid"`
		Links struct {
			Avatar struct {
				URL string `json:"href"`
			} `json:"avatar"`
		} `json:"links"`
		Username string `json:"username"`
		Name     string `json:"display_name"`
		Location string `json:"location"`
	}{}

	if err := json.NewDecoder(bytes.NewReader(bits)).Decode(&u); err != nil {
		return err
	}

	user.Name = u.Name
	user.NickName = u.Username
	user.AvatarURL = u.Links.Avatar.URL
	user.UserID = u.ID
	user.Location = u.Location

	return nil
}

func (p *Provider) getEmail(user *goth.User, sess *Session) error {
	req, err := http.NewRequest("GET", endpointEmail, nil)
	if err != nil {
		return err
	}
	authenticateRequest(req, sess)
	response, err := p.Client().Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s responded with a %d trying to fetch email addresses", p.providerName, response.StatusCode)
	}

	var mailList MailList
	err = json.NewDecoder(response.Body).Decode(&mailList)
	if err != nil {
		return err
	}

	for _, emailAddress := range mailList.Values {
		if emailAddress.IsPrimary && emailAddress.IsConfirmed {
			user.Email = emailAddress.Email
			return nil
		}
	}

	return fmt.Errorf("%s did not return any confirmed, primary email address", p.providerName)
}

func authenticateRequest(req *http.Request, sess *Session) {
	req.Header.Add("Authorization", "Bearer "+sess.AccessToken)
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

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
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
