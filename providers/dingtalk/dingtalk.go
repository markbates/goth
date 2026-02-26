// Package dingtalk implements the OAuth2 protocol for authenticating users through DingTalk.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
//
// # Configuration
//
// To use the DingTalk provider, you need to create an application in the DingTalk Open Platform (https://open.dingtalk.com/):
//  1. Register a corporate/organization application to get AppKey and AppSecret
//  2. Set callback URL: http://your-domain/auth/dingtalk/callback
//  3. Request these necessary API permissions:
//     - Contact.User.Read (必须/Required)
//     - Contact.Member.Read (必须/Required)
//
// # Example
//
//	// Basic use:
//	dingTalkProvider := dingtalk.New(
//	    os.Getenv("DINGTALK_KEY"),
//	    os.Getenv("DINGTALK_SECRET"),
//	    "http://localhost:3000/auth/dingtalk/callback",
//	    "", // empty string if you don't need corporate ID verification
//	    "openid" // minimum scope
//	)
//
//	// With corporate verification (limit to specific company):
//	dingTalkProvider := dingtalk.New(
//	    os.Getenv("DINGTALK_KEY"),
//	    os.Getenv("DINGTALK_SECRET"),
//	    "http://localhost:3000/auth/dingtalk/callback",
//	    os.Getenv("DINGTALK_CORP_ID"), // corporate ID for verification
//	    "openid",
//	    "corpid" // needed for corporate verification
//	)
//
//	// Enable debug mode for detailed logging
//	dingTalkProvider.Debug(true)
//
//	goth.UseProviders(dingTalkProvider)
//
// # Environment Variables
//
//	DINGTALK_KEY: Your DingTalk application's client key/app key
//	DINGTALK_SECRET: Your DingTalk application's client secret/app secret
//	DINGTALK_CORP_ID: (Optional) For corporate ID verification, to limit authentication to a specific company
//
// See the examples/main.go file for a working example of this provider.
package dingtalk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// These vars define the Authentication, Token, and API URLS for DingTalk.
// See: https://open.dingtalk.com/document/orgapp/tutorial-obtaining-user-personal-information
var (
	AuthURL    = "https://login.dingtalk.com/oauth2/auth"
	TokenURL   = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
	ProfileURL = "https://api.dingtalk.com/v1.0/contact/users/me"
)

// Logger for Debug output
var logger = log.New(os.Stdout, "[DingTalk Debug] ", log.LstdFlags|log.Lshortfile)

// New creates a new DingTalk provider, and sets up important connection details.
// You should always call `dingtalk.New` to get a new Provider. Never try to create
// one manually.
//
// When using with "corpid" scope, include "openid" and "corpid" in scopes parameter.
func New(clientKey, secret, callbackURL string, expectedCorpID string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, ProfileURL, expectedCorpID, scopes...)
}

// NewWithCorpID creates a new DingTalk provider with company ID verification.
// If expectedCorpID is non-empty, the provider will verify that authenticated users
// belong to the specified company. Authentication will fail if the user's corpID doesn't match.
//
// Use this constructor when you need to restrict access to users from a specific company.
// Be sure to include "openid" and "corpid" in the scopes parameter.
func NewWithCorpID(clientKey, secret, callbackURL, expectedCorpID string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, ProfileURL, expectedCorpID, "openid", "corpid")
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
// If expectedCorpID is non-empty, the provider will verify that authenticated users
// belong to the specified company.
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, profileURL, expectedCorpID string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:      clientKey,
		Secret:         secret,
		CallbackURL:    callbackURL,
		providerName:   "dingtalk",
		profileURL:     profileURL,
		debug:          false,
		expectedCorpID: expectedCorpID,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing DingTalk.
type Provider struct {
	ClientKey      string
	Secret         string
	CallbackURL    string
	HTTPClient     *http.Client
	config         *oauth2.Config
	providerName   string
	profileURL     string
	debug          bool
	expectedCorpID string // Corporate ID to validate against for company-specific authentication
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

// Debug sets the debug mode
func (p *Provider) Debug(debug bool) {
	p.debug = debug
}

// logDebug prints debug information
func (p *Provider) logDebug(format string, v ...interface{}) {
	if p.debug {
		logger.Printf(format, v...)
	}
}

// BeginAuth asks DingTalk for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	url := p.config.AuthCodeURL(state)

	// Add prompt=consent parameter to force showing the consent screen every time
	if !strings.Contains(url, "prompt=") {
		if strings.Contains(url, "?") {
			url += "&prompt=consent"
		} else {
			url += "?prompt=consent"
		}
	}

	p.logDebug("Authorization URL with consent prompt: %s", url)
	session := &Session{
		AuthURL:        url,
		ExpectedCorpID: p.expectedCorpID,
	}
	return session, nil
}

// FetchUser will go to DingTalk and access basic information about the user.
// If expectedCorpID is set and the user's corpID doesn't match, an error will be returned.
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

	p.logDebug("Starting to fetch user info, AccessToken: %s", user.AccessToken[:10]+"...")

	// Get user information
	reqProfile, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		p.logDebug("Failed to create request: %v", err)
		return user, err
	}

	reqProfile.Header.Add("x-acs-dingtalk-access-token", sess.AccessToken)
	reqProfile.Header.Add("Content-Type", "application/json")

	p.logDebug("Sending request for user info: %s", p.profileURL)
	p.logDebug("Request headers: %v", reqProfile.Header)

	response, err := p.Client().Do(reqProfile)
	if err != nil {
		p.logDebug("Failed to send request: %v", err)
		return user, err
	}
	defer response.Body.Close()

	p.logDebug("Received response status code: %d", response.StatusCode)

	if response.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(response.Body)
		p.logDebug("API error response: %s", string(respBody))
		return user, fmt.Errorf("DingTalk API responded with a %d trying to fetch user information: %s",
			response.StatusCode, string(respBody))
	}

	bits, err := io.ReadAll(response.Body)
	if err != nil {
		p.logDebug("Failed to read response body: %v", err)
		return user, err
	}

	p.logDebug("Response content: %s", string(bits))

	// Parse user information directly from the profile response
	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		p.logDebug("Failed to parse JSON response: %v", err)
		return user, err
	}

	// Extract user fields directly
	userInfo := struct {
		UnionID   string `json:"unionId"`
		Email     string `json:"email"`
		Mobile    string `json:"mobile"`
		AvatarURL string `json:"avatarUrl"`
		Nick      string `json:"nick"`
		OpenID    string `json:"openId"`
	}{}

	if err := json.NewDecoder(bytes.NewReader(bits)).Decode(&userInfo); err != nil {
		p.logDebug("Failed to extract user fields: %v", err)
		return user, err
	}

	// Populate user struct
	user.Name = userInfo.Nick
	user.NickName = userInfo.Nick
	user.Email = userInfo.Email
	user.UserID = userInfo.UnionID
	user.AvatarURL = userInfo.AvatarURL

	// Add corpID from session to user data
	if sess.CorpID != "" && user.RawData != nil {
		user.RawData["corpId"] = sess.CorpID
	}

	p.logDebug("Successfully retrieved user info: Name=%s, Email=%s", user.Name, user.Email)
	return user, nil
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
	} else {
		// If no scope is provided, add the default "openid"
		c.Scopes = []string{"openid"}
	}

	return c
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	p.logDebug("Attempting to refresh token with refreshToken: %s...", refreshToken[:10])

	data := struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		RefreshToken string `json:"refreshToken"`
		GrantType    string `json:"grantType"`
	}{
		ClientID:     p.ClientKey,
		ClientSecret: p.Secret,
		RefreshToken: refreshToken,
		GrantType:    "refresh_token",
	}

	payload, err := json.Marshal(data)
	if err != nil {
		p.logDebug("Failed to marshal refresh token request: %v", err)
		return nil, err
	}

	req, err := http.NewRequest("POST", TokenURL, bytes.NewBuffer(payload))
	if err != nil {
		p.logDebug("Failed to create refresh token request: %v", err)
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")

	p.logDebug("Sending refresh token request")
	p.logDebug("Request body: %s", string(payload))

	resp, err := p.Client().Do(req)
	if err != nil {
		p.logDebug("Failed to send refresh token request: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	p.logDebug("Refresh token response status code: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		p.logDebug("Refresh token error response: %s", string(respBody))
		return nil, fmt.Errorf("DingTalk API responded with a %d trying to refresh token: %s",
			resp.StatusCode, string(respBody))
	}

	var tokenResponse struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int    `json:"expireIn"`
		CorpID       string `json:"corpId"` // Corporate ID from token response
	}

	respBody, _ := io.ReadAll(resp.Body)
	p.logDebug("Refresh token response: %s", string(respBody))

	err = json.NewDecoder(bytes.NewReader(respBody)).Decode(&tokenResponse)
	if err != nil {
		p.logDebug("Failed to parse refresh token response: %v", err)
		return nil, err
	}

	// Verify corporate ID if expected is set
	if p.expectedCorpID != "" && tokenResponse.CorpID != "" {
		if tokenResponse.CorpID != p.expectedCorpID {
			p.logDebug("Corporate ID verification failed during token refresh. Expected: %s, Got: %s",
				p.expectedCorpID, tokenResponse.CorpID)
			return nil, fmt.Errorf("user does not belong to the expected company (corpid mismatch)")
		}
		p.logDebug("Corporate ID verification succeeded during token refresh")
	}

	p.logDebug("Successfully refreshed token. New token: %s...", tokenResponse.AccessToken[:10])

	token := &oauth2.Token{
		AccessToken:  tokenResponse.AccessToken,
		RefreshToken: tokenResponse.RefreshToken,
		TokenType:    "Bearer",
	}

	// Add corpID as extra data
	if tokenResponse.CorpID != "" {
		extraData := map[string]interface{}{
			"corpId": tokenResponse.CorpID,
		}
		token = token.WithExtra(extraData)
	}

	return token, nil
}

// RefreshTokenAvailable refresh token is provided by DingTalk
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// GetCorpID retrieves the company ID from user data
// Returns the corpID and whether it was found
func GetCorpID(user goth.User) (string, bool) {
	if user.RawData == nil {
		return "", false
	}

	if corpID, ok := user.RawData["corpId"].(string); ok {
		return corpID, true
	}

	return "", false
}
