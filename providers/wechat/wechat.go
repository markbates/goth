package wechat

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	AuthURL  = "https://open.weixin.qq.com/connect/qrconnect"
	TokenURL = "https://api.weixin.qq.com/sns/oauth2/access_token"

	ScopeSnsapiLogin = "snsapi_login"

	ProfileURL = "https://api.weixin.qq.com/sns/userinfo"
)

type Provider struct {
	providerName string
	config       *oauth2.Config
	httpClient   *http.Client
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Lang         WechatLangType

	AuthURL    string
	TokenURL   string
	ProfileURL string
}

type WechatLangType string

const (
	WECHAT_LANG_CN WechatLangType = "cn"
	WECHAT_LANG_EN WechatLangType = "en"
)

// New creates a new Wechat provider, and sets up important connection details.
// You should always call `wechat.New` to get a new Provider. Never try to create
// one manually.
func New(clientID, clientSecret, redirectURL string, lang WechatLangType) *Provider {
	p := &Provider{
		providerName: "wechat",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Lang:         lang,
		AuthURL:      AuthURL,
		TokenURL:     TokenURL,
		ProfileURL:   ProfileURL,
	}
	p.config = newConfig(p)
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

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.httpClient)
}

// Debug is a no-op for the wechat package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks Wechat for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	params := url.Values{}
	params.Add("appid", p.ClientID)
	params.Add("response_type", "code")
	params.Add("state", state)
	params.Add("scope", ScopeSnsapiLogin)
	params.Add("redirect_uri", p.RedirectURL)
	params.Add("lang", string(p.Lang))
	session := &Session{
		AuthURL: fmt.Sprintf("%s?%s", p.AuthURL, params.Encode()),
	}
	return session, nil
}

// FetchUser will go to Wepay and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	s := session.(*Session)
	user := goth.User{
		AccessToken:  s.AccessToken,
		Provider:     p.Name(),
		RefreshToken: s.RefreshToken,
		ExpiresAt:    s.ExpiresAt,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	params := url.Values{}
	params.Add("access_token", s.AccessToken)
	params.Add("openid", s.Openid)
	params.Add("lang", string(p.Lang))

	url := fmt.Sprintf("%s?%s", p.ProfileURL, params.Encode())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return user, err
	}
	resp, err := p.Client().Do(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return user, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	err = userFromReader(resp.Body, &user)
	return user, err
}

func newConfig(provider *Provider) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  provider.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.AuthURL,
			TokenURL: provider.TokenURL,
		},
		Scopes: []string{},
	}

	c.Scopes = append(c.Scopes, ScopeSnsapiLogin)

	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Openid    string `json:"openid"`
		Nickname  string `json:"nickname"`
		Sex       int    `json:"sex"`
		Province  string `json:"province"`
		City      string `json:"city"`
		Country   string `json:"country"`
		AvatarURL string `json:"headimgurl"`
		Unionid   string `json:"unionid"`
		Code      int    `json:"errcode"`
		Msg       string `json:"errmsg"`
	}{}
	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	if len(u.Msg) > 0 {
		return fmt.Errorf("CODE: %d, MSG: %s", u.Code, u.Msg)
	}

	user.Email = fmt.Sprintf("%s@wechat.com", u.Openid)
	user.Name = u.Nickname
	user.UserID = u.Openid
	user.NickName = u.Nickname
	user.Location = u.City
	user.AvatarURL = u.AvatarURL
	user.RawData = map[string]interface{}{
		"Unionid": u.Unionid,
	}
	return nil
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {

	return nil, nil
}

func (p *Provider) fetchToken(code string) (*oauth2.Token, string, error) {

	params := url.Values{}
	params.Add("appid", p.ClientID)
	params.Add("secret", p.ClientSecret)
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	url := fmt.Sprintf("%s?%s", p.TokenURL, params.Encode())
	resp, err := p.Client().Get(url)

	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("wechat /gettoken returns code: %d", resp.StatusCode)
	}

	obj := struct {
		AccessToken string        `json:"access_token"`
		ExpiresIn   time.Duration `json:"expires_in"`
		Openid      string        `json:"openid"`
		Code        int           `json:"errcode"`
		Msg         string        `json:"errmsg"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return nil, "", err
	}
	if obj.Code != 0 {
		return nil, "", fmt.Errorf("CODE: %d, MSG: %s", obj.Code, obj.Msg)
	}

	token := &oauth2.Token{
		AccessToken: obj.AccessToken,
		Expiry:      time.Now().Add(obj.ExpiresIn * time.Second),
	}

	return token, obj.Openid, nil
}
