package lark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	appAccessTokenURL string = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/" // get app_access_token

	authURL         string = "https://open.feishu.cn/open-apis/authen/v1/authorize"                 // obtain authorization code
	tokenURL        string = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token"         // get user_access_token
	refreshTokenURL string = "https://open.feishu.cn/open-apis/authen/v1/oidc/refresh_access_token" // refresh user_access_token
	endpointProfile string = "https://open.feishu.cn/open-apis/authen/v1/user_info"                 // get user info
)

// Lark is the implementation of `goth.Provider` for accessing Lark
type Lark interface {
	GetAppAccessToken() error // get app access token
}

// Provider is the implementation of `goth.Provider` for accessing Lark
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string

	appAccessToken *appAccessToken
}

// New creates a new Lark provider and sets up important connection details.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:      clientKey,
		Secret:         secret,
		CallbackURL:    callbackURL,
		providerName:   "lark",
		appAccessToken: &appAccessToken{},
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
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

	if len(scopes) > 0 {
		c.Scopes = append(c.Scopes, scopes...)
	}
	return c
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

func (p *Provider) Name() string {
	return p.providerName
}

func (p *Provider) SetName(name string) {
	p.providerName = name
}

type appAccessToken struct {
	Token     string
	ExpiresAt time.Time
	rMutex    sync.RWMutex
}

type appAccessTokenReq struct {
	AppID     string `json:"app_id"`     // 自建应用的 app_id
	AppSecret string `json:"app_secret"` // 自建应用的 app_secret
}

type appAccessTokenResp struct {
	Code           int    `json:"code"`             // 错误码
	Msg            string `json:"msg"`              // 错误信息
	AppAccessToken string `json:"app_access_token"` // 用于调用应用级接口的 app_access_token
	Expire         int64  `json:"expire"`           // app_access_token 的过期时间
}

// GetAppAccessToken get lark app access token
func (p *Provider) GetAppAccessToken() error {
	// get from cache app access token
	p.appAccessToken.rMutex.RLock()
	if time.Now().Before(p.appAccessToken.ExpiresAt) {
		p.appAccessToken.rMutex.RUnlock()
		return nil
	}
	p.appAccessToken.rMutex.RUnlock()

	reqBody, err := json.Marshal(&appAccessTokenReq{
		AppID:     p.ClientKey,
		AppSecret: p.Secret,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, appAccessTokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create app access token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Client().Do(req)
	if err != nil {
		return fmt.Errorf("failed to send app access token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code while fetching app access token: %d", resp.StatusCode)
	}

	tokenResp := new(appAccessTokenResp)
	if err = json.NewDecoder(resp.Body).Decode(tokenResp); err != nil {
		return fmt.Errorf("failed to decode app access token response: %w", err)
	}

	if tokenResp.Code != 0 {
		return fmt.Errorf("failed to get app access token: code:%v msg: %s", tokenResp.Code, tokenResp.Msg)
	}

	// update local cache
	expirationDuration := time.Duration(tokenResp.Expire) * time.Second
	p.appAccessToken.rMutex.Lock()
	p.appAccessToken.Token = tokenResp.AppAccessToken
	p.appAccessToken.ExpiresAt = time.Now().Add(expirationDuration)
	p.appAccessToken.rMutex.Unlock()

	return nil
}

func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	// build lark auth url
	u, err := url.Parse(p.config.AuthCodeURL(state))
	if err != nil {
		panic(err)
	}
	query := u.Query()
	query.Del("response_type")
	query.Del("client_id")
	query.Add("app_id", p.ClientKey)
	u.RawQuery = query.Encode()

	return &Session{
		AuthURL: u.String(),
	}, nil
}

func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

func (p *Provider) Debug(b bool) {
}

type getUserAccessTokenResp struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	Scope            string `json:"scope"`
}

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	if err := p.GetAppAccessToken(); err != nil {
		return nil, fmt.Errorf("failed to get app access token: %w", err)
	}
	reqBody := strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"` + refreshToken + `"}`)

	req, err := http.NewRequest(http.MethodPost, refreshTokenURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.appAccessToken.Token))

	resp, err := p.Client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send refresh token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code while refreshing token: %d", resp.StatusCode)
	}

	var oauthResp commResponse[getUserAccessTokenResp]
	err = json.NewDecoder(resp.Body).Decode(&oauthResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refreshed token: %w", err)
	}
	if oauthResp.Code != 0 {
		return nil, fmt.Errorf("failed to refresh token: code:%v msg: %s", oauthResp.Code, oauthResp.Msg)
	}

	token := oauth2.Token{
		AccessToken:  oauthResp.Data.AccessToken,
		RefreshToken: oauthResp.Data.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(oauthResp.Data.ExpiresIn) * time.Second),
	}

	return &token, nil
}

func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

type commResponse[T any] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

type larkUser struct {
	OpenID    string `json:"open_id"`
	UnionID   string `json:"union_id"`
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	Email     string `json:"enterprise_email"`
	AvatarURL string `json:"avatar_url"`
	Mobile    string `json:"mobile,omitempty"`
}

// FetchUser will go to Lark and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}
	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, fmt.Errorf("%s failed to create request: %w", p.providerName, err)
	}
	req.Header.Set("Authorization", "Bearer "+user.AccessToken)

	resp, err := p.Client().Do(req)
	if err != nil {
		return user, fmt.Errorf("%s failed to get user information: %w", p.providerName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return user, fmt.Errorf("failed to read response body: %w", err)
	}

	var oauthResp commResponse[larkUser]
	if err = json.Unmarshal(responseBytes, &oauthResp); err != nil {
		return user, fmt.Errorf("failed to decode user info: %w", err)
	}
	if oauthResp.Code != 0 {
		return user, fmt.Errorf("failed to get user info: code:%v msg: %s", oauthResp.Code, oauthResp.Msg)
	}

	u := oauthResp.Data
	user.UserID = u.UserID
	user.Name = u.Name
	user.Email = u.Email
	user.AvatarURL = u.AvatarURL
	user.NickName = u.Name

	if err = json.Unmarshal(responseBytes, &user.RawData); err != nil {
		return user, err
	}
	return user, nil
}
