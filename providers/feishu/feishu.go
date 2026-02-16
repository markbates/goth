package feishu

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// See: https://open.feishu.cn/document/sso/web-application-sso/login-overview
var (
	AuthURL    = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	TokenURL   = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
	ProfileURL = "https://open.feishu.cn/open-apis/authen/v1/user_info"
)

// Provider is the implementation of `goth.Provider` for accessing Feishu.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	AuthURL      string
	TokenURL     string
	ProfileURL   string
}

// New creates a new Feishu provider, and sets up important connection details.
// You should always call `feishu.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, ProfileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, ProfileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "feishu",
		AuthURL:      AuthURL,
		TokenURL:     TokenURL,
		ProfileURL:   ProfileURL,
	}
	p.config = newConfig(p, scopes)
	return p
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.AuthURL,
			TokenURL: provider.TokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		c.Scopes = append(c.Scopes, scopes...)
	} else {
		// If no scope is provided, add the default "auth:user.id:read"
		c.Scopes = []string{"auth:user.id:read"}
	}

	return c
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// BeginAuth asks Feishu for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// Debug is a no-op for the amazon package.
func (p *Provider) Debug(debug bool) {}

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

// RefreshTokenAvailable refresh token is provided by Feishu
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

type feishuUser struct {
	Name            string `json:"name"`
	EnName          string `json:"en_name"`
	AvatarURL       string `json:"avatar_url"`
	AvatarThumb     string `json:"avatar_thumb"`
	AvatarMiddle    string `json:"avatar_middle"`
	AvatarBig       string `json:"avatar_big"`
	OpenID          string `json:"open_id"`
	UnionID         string `json:"union_id"`
	Email           string `json:"email,omitempty"`
	EnterpriseEmail string `json:"enterprise_email,omitempty"`
	UserID          string `json:"user_id,omitempty"`
	Mobile          string `json:"mobile,omitempty"`
	TenantKey       string `json:"tenant_key"`
	EmployeeNo      string `json:"employee_no,omitempty"`
}

// FetchUser will go to Feishu and access basic information about the user.
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

	// Get user information
	reqProfile, err := http.NewRequest("GET", p.ProfileURL, nil)
	if err != nil {
		return user, err
	}

	reqProfile.Header.Add("Authorization", fmt.Sprintf("Bearer %s", user.AccessToken))
	reqProfile.Header.Add("Content-Type", "application/json")

	response, err := p.Client().Do(reqProfile)
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

	resBody := struct {
		Code int                    `json:"code"`
		Msg  string                 `json:"msg"`
		Data map[string]interface{} `json:"data"`
	}{}
	err = json.Unmarshal(bits, &resBody)
	if err != nil {
		return user, err
	}
	if resBody.Code != 0 {
		return user, fmt.Errorf("%s", resBody.Msg)
	}

	dataBits, err := json.Marshal(resBody.Data)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(dataBits), &user)
	return user, err
}

func userFromReader(r io.Reader, user *goth.User) error {
	// Extract user fields directly
	u := feishuUser{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}
	bits, _ := json.Marshal(u)
	json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)

	// Populate user struct
	user.Email = u.EnterpriseEmail
	user.Name = u.Name
	user.NickName = u.Name
	user.UserID = u.OpenID
	user.AvatarURL = u.AvatarURL

	return nil
}
