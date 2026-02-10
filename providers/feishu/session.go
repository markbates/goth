package feishu

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/markbates/goth"
)

type Session struct {
	AuthURL               string
	AccessToken           string
	RefreshToken          string
	ExpiresAt             time.Time
	RefreshTokenExpiresAt time.Time
}

func (s *Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("feishu: missing AuthURL")
	}
	return s.AuthURL, nil
}

func (s *Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	reqBody := strings.NewReader(`{"grant_type":"authorization_code","code":"` + params.Get("code") + `"}`)
	req, err := http.NewRequest(http.MethodPost, tokenURL, reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to create refresh token request: %w", err)
	}
	if err = p.GetAppAccessToken(); err != nil {
		return "", fmt.Errorf("failed to get app access token: %w", err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", p.appAccessToken.Token))
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	resp, err := p.Client().Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send refresh token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code while authorizing: %d", resp.StatusCode)
	}

	var feishuCommResp commResponse[getUserAccessTokenResp]
	err = json.NewDecoder(resp.Body).Decode(&feishuCommResp)
	if err != nil {
		return "", fmt.Errorf("failed to decode commResponse: %w", err)
	}
	if feishuCommResp.Code != 0 {
		return "", fmt.Errorf("failed to get accessToken: code:%v msg: %s", feishuCommResp.Code, feishuCommResp.Msg)
	}

	s.AccessToken = feishuCommResp.Data.AccessToken
	s.RefreshToken = feishuCommResp.Data.RefreshToken
	s.ExpiresAt = time.Now().Add(time.Duration(feishuCommResp.Data.ExpiresIn) * time.Second)
	s.RefreshTokenExpiresAt = time.Now().Add(time.Duration(feishuCommResp.Data.RefreshExpiresIn) * time.Second)
	return s.AccessToken, nil
}
