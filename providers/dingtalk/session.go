package dingtalk

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with DingTalk.
type Session struct {
	AuthURL        string
	AccessToken    string
	RefreshToken   string
	ExpiresAt      time.Time
	CorpID         string // Corporate ID of the authenticated user
	ExpectedCorpID string // Expected Corporate ID for validation
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the DingTalk provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with DingTalk and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)

	// DingTalk uses a non-standard OAuth2 flow, using JSON request to get the token
	code := params.Get("code")
	if code == "" {
		return "", errors.New("no code received")
	}

	p.logDebug("Authorizing with code: %s", code)

	data := struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		Code         string `json:"code"`
		GrantType    string `json:"grantType"`
	}{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		Code:         code,
		GrantType:    "authorization_code",
	}

	payload, err := json.Marshal(data)
	if err != nil {
		p.logDebug("Failed to marshal authorization data: %v", err)
		return "", err
	}

	client := p.Client()
	req, err := http.NewRequest("POST", "https://api.dingtalk.com/v1.0/oauth2/userAccessToken", strings.NewReader(string(payload)))
	if err != nil {
		p.logDebug("Failed to create authorization request: %v", err)
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")

	p.logDebug("Sending authorization request")
	p.logDebug("Request body: %s", string(payload))

	resp, err := client.Do(req)
	if err != nil {
		p.logDebug("Failed to send authorization request: %v", err)
		return "", err
	}
	defer resp.Body.Close()

	p.logDebug("Authorization response status code: %d", resp.StatusCode)

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		p.logDebug("Authorization error response: %s", string(respBody))
		return "", fmt.Errorf("DingTalk auth error (status %d): %s", resp.StatusCode, string(respBody))
	}

	respBody, _ := io.ReadAll(resp.Body)
	p.logDebug("Authorization response: %s", string(respBody))

	var tokenResponse struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int    `json:"expireIn"`
		CorpID       string `json:"corpId"` // Corporate ID field from token response
	}

	if err = json.NewDecoder(strings.NewReader(string(respBody))).Decode(&tokenResponse); err != nil {
		p.logDebug("Failed to parse authorization response: %v", err)
		return "", err
	}

	s.AccessToken = tokenResponse.AccessToken
	s.RefreshToken = tokenResponse.RefreshToken
	s.ExpiresAt = time.Now().Add(time.Second * time.Duration(tokenResponse.ExpiresIn))
	s.CorpID = tokenResponse.CorpID

	p.logDebug("Successfully authorized. Access token: %s...", s.AccessToken[:10])

	// Verify Corporate ID if expected is set
	if s.ExpectedCorpID != "" && s.CorpID != "" {
		if s.CorpID != s.ExpectedCorpID {
			p.logDebug("Corporate ID verification failed. Expected: %s, Got: %s", s.ExpectedCorpID, s.CorpID)
			return "", fmt.Errorf("user does not belong to the expected company (corpid mismatch)")
		}
		p.logDebug("Corporate ID verification succeeded")
	}

	return s.AccessToken, nil
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
