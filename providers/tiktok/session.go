package tiktok

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with TikTok
type Session struct {
	AuthURL          string
	AccessToken      string
	ExpiresAt        time.Time
	OpenID           string
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the TikTok provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with TikTok and return the access token to be stored for future use. Note that
// we call the endpoints directly vs calling *oauth2.Config.Exchange() due to inconsistent TikTok param names.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)

	// Set up the url params to post to get a new access token from a code
	v := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {params.Get("code")},
	}
	if p.config.RedirectURL != "" {
		v.Set("redirect_uri", p.config.RedirectURL)
	}

	req, err := http.NewRequest(http.MethodPost, endpointToken, nil)
	if err != nil {
		return "", err
	}
	v.Add("client_key", p.config.ClientID)
	v.Add("client_secret", p.config.ClientSecret)

	req.URL.RawQuery = v.Encode()
	response, err := p.GetClient().Do(req)
	if err != nil {
		return "", err
	}

	tokenResp := struct {
		Data struct {
			OpenID           string `json:"open_id"`
			Scope            string `json:"scope"`
			AccessToken      string `json:"access_token"`
			ExpiresIn        int64  `json:"expires_in"`
			RefreshToken     string `json:"refresh_token"`
			RefreshExpiresIn int64  `json:"refresh_expires_in"`
		} `json:"data"`
	}{}

	// Get the body bytes in case we have to parse an error response
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	err = json.Unmarshal(bodyBytes, &tokenResp)
	if err != nil {
		return "", err
	}

	// If we do not have an access token we assume we have an error response payload
	if tokenResp.Data.AccessToken == "" {
		return "", handleErrorResponse(bodyBytes)
	}

	// Create and Bind the Access Token
	s.AccessToken = tokenResp.Data.AccessToken
	s.ExpiresAt = time.Now().UTC().Add(time.Second * time.Duration(tokenResp.Data.ExpiresIn))
	s.OpenID = tokenResp.Data.OpenID
	s.RefreshToken = tokenResp.Data.RefreshToken
	s.RefreshExpiresAt = time.Now().UTC().Add(time.Second * time.Duration(tokenResp.Data.RefreshExpiresIn))
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
