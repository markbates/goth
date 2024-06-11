package classlink

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const infoURL = "https://nodeapi.classlink.com/v2/my/info"

// Provider is an implementation of
type Provider struct {
	ClientKey    string
	ClientSecret string
	CallbackURL  string
	HTTPClient   *http.Client
	providerName string
	config       *oauth2.Config
}

func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	prov := &Provider{
		ClientKey:    clientKey,
		ClientSecret: secret,
		CallbackURL:  callbackURL,
		providerName: "classlink",
	}
	prov.config = newConfig(prov, scopes)
	return prov
}

func (p Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

func (p Provider) Name() string {
	return p.providerName
}

func (p Provider) SetName(name string) {
	p.providerName = name
}

func (p Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	return &Session{
		AuthURL: url,
	}, nil
}

func (p Provider) UnmarshalSession(s string) (goth.Session, error) {
	var sess Session
	err := json.Unmarshal([]byte(s), &sess)

	if err != nil {
		return nil, err
	}

	return &sess, nil
}

// classLinkUser contains all relevant fields from the ClassLink response
// to
type classLinkUser struct {
	UserID      int    `json:"UserId"`
	Email       string `json:"Email"`
	DisplayName string `json:"DisplayName"`
	FirstName   string `json:"FirstName"`
	LastName    string `json:"LastName"`
}

func (p Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}

	if user.AccessToken == "" {
		// Data is not yet retrieved, since accessToken is still empty.
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", infoURL, nil)
	if err != nil {
		return user, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sess.AccessToken))

	resp, err := p.Client().Do(req)
	if err != nil {
		return user, err
	}

	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	var u classLinkUser
	if err := json.Unmarshal(bytes, &user.RawData); err != nil {
		return user, err
	}

	if err := json.Unmarshal(bytes, &u); err != nil {
		return user, err
	}

	user.UserID = fmt.Sprintf("%d", u.UserID)
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.Email = u.Email
	user.Name = u.DisplayName
	return user, nil
}

func (p Provider) Debug(b bool) {}

func (p Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("refresh token is not provided by ClassLink")
}

func (p Provider) RefreshTokenAvailable() bool {
	return false
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://launchpad.classlink.com/oauth2/v2/auth",
			TokenURL: "https://launchpad.classlink.com/oauth2/v2/token",
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		c.Scopes = append(c.Scopes, scopes...)
	} else {
		c.Scopes = append(c.Scopes, "profile")
	}

	return c
}
