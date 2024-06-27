// Package wecom implements the qrConnect protocol for authenticating users through WeCom.
// Reference: https://work.weixin.qq.com/api/doc/90000/90135/90988
package wecom

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Avyukth/goth"
	"golang.org/x/oauth2"
)

var (
	AuthURL = "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"
	BaseURL = "https://qyapi.weixin.qq.com/cgi-bin"
)

// New creates a new WeCom provider, and sets up important connection details.
func New(corpID, secret, agentID, callbackURL string) *Provider {
	return &Provider{
		ClientKey:    corpID,
		Secret:       secret,
		AgentID:      agentID,
		CallbackURL:  callbackURL,
		providerName: "wecom",
		authURL:      AuthURL,
		baseURL:      BaseURL,
	}
}

// Provider is the implementation of `goth.Provider` for accessing WeCom.
type Provider struct {
	ClientKey    string
	Secret       string
	AgentID      string
	CallbackURL  string
	HTTPClient   *http.Client
	providerName string

	// token caches the access_token
	token *oauth2.Token

	authURL string
	baseURL string
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

// Debug is a no-op for the wecom package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks WeCom for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	params := url.Values{}
	params.Add("appid", p.ClientKey)
	params.Add("agentid", p.AgentID)
	params.Add("state", state)
	params.Add("redirect_uri", p.CallbackURL)
	session := &Session{
		AuthURL: fmt.Sprintf("%s?%s", p.authURL, params.Encode()),
	}
	return session, nil
}

// FetchUser will go to WeCom and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}

	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	params := url.Values{}
	params.Add("access_token", user.AccessToken)
	params.Add("userid", sess.UserID)
	resp, err := p.Client().Get(fmt.Sprintf("%s/user/get?%s", p.baseURL, params.Encode()))
	if err != nil {
		return user, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("wecom /user/get returns code: %d", resp.StatusCode)
	}

	if err := userFromReader(resp.Body, &user); err != nil {
		return user, err
	}

	return user, nil
}

// RefreshToken refresh token is not provided by WeCom
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("refresh token is not provided by wecom")
}

// RefreshTokenAvailable refresh token is not provided by WeCom
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

func (p *Provider) fetchToken() (*oauth2.Token, error) {
	if p.token != nil && p.token.Valid() {
		return p.token, nil
	}

	params := url.Values{}
	params.Add("corpid", p.ClientKey)
	params.Add("corpsecret", p.Secret)
	resp, err := p.Client().Get(fmt.Sprintf("%s/gettoken?%s", p.baseURL, params.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wecom /gettoken returns code: %d", resp.StatusCode)
	}

	obj := struct {
		AccessToken string        `json:"access_token"`
		ExpiresIn   time.Duration `json:"expires_in"`
		Code        int           `json:"errcode"`
		Msg         string        `json:"errmsg"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return nil, err
	}
	if obj.Code != 0 {
		return nil, fmt.Errorf("CODE: %d, MSG: %s", obj.Code, obj.Msg)
	}

	p.token = &oauth2.Token{
		AccessToken: obj.AccessToken,
		Expiry:      time.Now().Add(obj.ExpiresIn * time.Second),
	}

	return p.token, nil
}

func (p *Provider) fetchUserID(session goth.Session, code string) (string, error) {
	sess := session.(*Session)
	params := url.Values{}
	params.Add("access_token", sess.AccessToken)
	params.Add("code", code)
	resp, err := p.Client().Get(fmt.Sprintf("%s/user/getuserinfo?%s", p.baseURL, params.Encode()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("wecom /getuserinfo returns code: %d", resp.StatusCode)
	}

	obj := struct {
		UserId string `json:"UserId"`
		Code   int    `json:"errcode"`
		Msg    string `json:"errmsg"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return "", err
	}
	if obj.Code != 0 {
		return "", fmt.Errorf("CODE: %d, MSG: %s", obj.Code, obj.Msg)
	}

	return obj.UserId, nil
}

func userFromReader(reader io.Reader, user *goth.User) error {
	obj := struct {
		UserId  string `json:"userid"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Alias   string `json:"alias"`
		Avatar  string `json:"avatar"`
		Address string `json:"address"`
		Code    int    `json:"errcode"`
		Msg     string `json:"errmsg"`
	}{}

	if err := json.NewDecoder(reader).Decode(&obj); err != nil {
		return err
	}
	if obj.Code != 0 {
		return fmt.Errorf("CODE: %d, MSG: %s", obj.Code, obj.Msg)
	}

	user.Name = obj.Name
	user.NickName = obj.Alias
	user.Email = obj.Email
	user.UserID = obj.UserId
	user.AvatarURL = obj.Avatar
	user.Location = obj.Address

	return nil
}
