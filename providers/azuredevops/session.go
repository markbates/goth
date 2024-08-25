package azuredevops

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/markbates/goth"
)

type exchangeTokenResponse struct {
	Error            string `json:"Error"`
	ErrorDescription string `json:"ErrorDescription"`
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        string `json:"expires_in"`
	Scopes           string `json:"scope"`
}

// Session stores data during the auth process with Azure.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Azure provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Azure and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	v := url.Values{
		"client_assertion_type": CondVal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		"grant_type":            CondVal("urn:ietf:params:oauth:grant-type:jwt-bearer"),
		"assertion":             CondVal(params.Get("code")),
		"redirect_uri":          CondVal(p.config.RedirectURL),
	}

	authData, err := retrieveAuthData(p, tokenURL, v)
	if err != nil {
		return "", err
	}

	expiresIn, err := strconv.Atoi(authData.ExpiresIn)
	if err != nil {
		return "", err
	}

	s.AccessToken = authData.AccessToken
	s.RefreshToken = authData.RefreshToken
	s.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return s.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// CondVal convert string in string array
func CondVal(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// Custom implementation for azure to get access token and user data
// Azure provides user data along with access token, no separate api available
func retrieveAuthData(p *Provider, TokenURL string, v url.Values) (exchangeTokenResponse, error) {
	v.Set("client_assertion", p.Secret)
	req, err := http.NewRequest("POST", TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return exchangeTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	r, err := p.Client().Do(req)
	if err != nil {
		return exchangeTokenResponse{}, err
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return exchangeTokenResponse{}, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return exchangeTokenResponse{}, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	var response exchangeTokenResponse

	err = json.Unmarshal(body, &response)

	if err != nil {
		return exchangeTokenResponse{}, err
	}
	return response, nil
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
