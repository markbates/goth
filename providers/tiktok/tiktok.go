// Package tiktok implements the OAuth2 protocol for authenticating users through TikTok.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package tiktok

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const (
	endpointAuth     = "https://open-api.tiktok.com/platform/oauth/connect/"
	endpointToken    = "https://open-api.tiktok.com/oauth/access_token/"
	endpointRefresh  = "https://open-api.tiktok.com/oauth/refresh_token/"
	endpointUserInfo = "https://open-api.tiktok.com/oauth/userinfo/"

	ScopeUserInfoBasic    = "user.info.basic"
	ScopeVideoList        = "video.list"
	ScopeVideoUpload      = "video.upload"
	ScopeShareSoundCreate = "share.sound.create"
)

// Provider is the implementation of `goth.Provider` for accessing TikTok
type Provider struct {
	CallbackURL  string
	Client       *http.Client
	ClientKey    string
	ClientSecret string
	config       *oauth2.Config
	providerName string
}

// New creates a new TikTok provider, and sets up connection details.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		ClientSecret: secret,
		CallbackURL:  callbackURL,
		providerName: "tiktok",
	}
	p.config = newConfig(p, scopes)
	return p
}

// Name is the name used to retrieve this provider.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) GetClient() *http.Client {
	return goth.HTTPClientWithFallBack(p.Client)
}

// Debug TODO
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks TikTok for an authentication end-point. Note that we create our own URL string instead
// of calling oauth2.AuthCodeURL() due to TikTok param name requirements.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	var buf bytes.Buffer
	buf.WriteString(p.config.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"code"},
		"client_key":    {p.config.ClientID},
		"state":         {state},
	}

	if p.config.RedirectURL != "" {
		v.Set("redirect_uri", p.config.RedirectURL)
	}

	// Note scopes are CSVs
	if len(p.config.Scopes) > 0 {
		v.Set("scope", strings.Join(p.config.Scopes, ","))
	}

	if strings.Contains(p.config.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return &Session{
		AuthURL: buf.String(),
	}, nil
}

// FetchUser will go to TikTok and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		ExpiresAt:    sess.ExpiresAt,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		UserID:       sess.OpenID,
	}

	// data is not yet retrieved since accessToken is still empty
	if user.AccessToken == "" || user.UserID == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken and userID", p.providerName)
	}

	// Set up the url params to post to get a new access token from a code
	v := url.Values{
		"access_token": {user.AccessToken},
		"open_id":      {user.UserID},
	}
	response, err := p.GetClient().Get(endpointUserInfo + "?" + v.Encode())
	if err != nil {
		return user, err
	}

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	err = userFromReader(response.Body, &user)
	response.Body.Close()
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	u := struct {
		Data struct {
			OpenID      string `json:"open_id"`
			Avatar      string `json:"avatar"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
	}{}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bodyBytes, &u)
	if err != nil {
		return err
	}
	user.AvatarURL = u.Data.Avatar
	user.Name = u.Data.DisplayName
	user.NickName = u.Data.DisplayName

	// On no display name, we assume an error response. TikTok returns error codes and descriptions inside
	// the same struct/body. Sigh...refer https://developers.tiktok.com/doc/login-kit-user-info-basic
	if user.Name == "" {
		return handleErrorResponse(bodyBytes)
	}

	// Bind the all the bytes to the raw data returning err
	return json.Unmarshal(bodyBytes, &user.RawData)
}

func newConfig(p *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.ClientKey,
		ClientSecret: p.ClientSecret,
		RedirectURL:  p.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL: endpointAuth,
		},
		Scopes: []string{ScopeUserInfoBasic},
	}

	// Note that the "user.info.basic" scope is always bound so don't dupe
	for _, scope := range scopes {
		if scope != ScopeUserInfoBasic {
			c.Scopes = append(c.Scopes, scope)
		}
	}

	return c
}

// RefreshToken will refresh a TikTok access token.
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	req, err := http.NewRequest(http.MethodPost, endpointRefresh, nil)
	if err != nil {
		return nil, err
	}

	// Set up the url params to post to get a new access token from a code
	v := url.Values{
		"client_key":    {p.config.ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req.URL.RawQuery = v.Encode()
	refreshResponse, err := p.GetClient().Do(req)
	if err != nil {
		return nil, err
	}

	// We get the body bytes in case we need to parse an error response
	bodyBytes, err := io.ReadAll(refreshResponse.Body)
	if err != nil {
		return nil, err
	}
	defer refreshResponse.Body.Close()

	refresh := struct {
		Data struct {
			OpenID           string `json:"open_id"`
			Scope            string `json:"scope"`
			AccessToken      string `json:"access_token"`
			ExpiresIn        int64  `json:"expires_in"`
			RefreshToken     string `json:"refresh_token"`
			RefreshExpiresIn int64  `json:"refresh_expires_in"`
		} `json:"data"`
	}{}
	err = json.Unmarshal(bodyBytes, &refresh)
	if err != nil {
		return nil, err
	}

	// If we do not have an access token we assume we have an error response payload
	if refresh.Data.AccessToken == "" {
		return nil, handleErrorResponse(bodyBytes)
	}

	token := &oauth2.Token{
		AccessToken:  refresh.Data.AccessToken,
		TokenType:    "Bearer",
		RefreshToken: refresh.Data.RefreshToken,
		Expiry:       time.Now().Add(time.Second * time.Duration(refresh.Data.ExpiresIn)),
	}

	tokenExtra := map[string]interface{}{
		"open_id":            refresh.Data.OpenID,
		"scope":              refresh.Data.Scope,
		"refresh_expires_in": refresh.Data.RefreshExpiresIn,
	}

	return token.WithExtra(tokenExtra), nil
}

// RefreshTokenAvailable refresh token
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

func handleErrorResponse(data []byte) error {
	errResp := struct {
		Data struct {
			Captcha     string `json:"captcha"`
			DescURL     string `json:"desc_url"`
			Description string `json:"description"`
			ErrorCode   int    `json:"error_code"`
		} `json:"data"`
		Message string `json:"message"`
	}{}
	if err := json.Unmarshal(data, &errResp); err != nil {
		return err
	}

	return fmt.Errorf("%s [%d]", errResp.Data.Description, errResp.Data.ErrorCode)
}
