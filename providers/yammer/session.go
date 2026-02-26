package yammer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/markbates/goth"
)

// Session stores data during the auth process with Yammer.
type Session struct {
	AuthURL     string
	AccessToken string
}

var _ goth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Yammer provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Yammer and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         CondVal(params.Get("code")),
		"redirect_uri": CondVal(p.config.RedirectURL),
		"scope":        CondVal(strings.Join(p.config.Scopes, " ")),
	}
	// Cant use standard auth2 implementation as yammer returns access_token as json rather than string
	// stand methods are throwing exception
	// token, err := p.config.Exchange(goth.ContextForClient(p.Client), params.Get("code"))
	autData, err := retrieveAuthData(p, tokenURL, v)
	if err != nil {
		return "", err
	}
	token := autData["access_token"]["token"].(string)
	s.AccessToken = token
	return token, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// Custom implementation for yammer to get access token and user data
// Yammer provides user data along with access token, no separate api available
func retrieveAuthData(p *Provider, TokenURL string, v url.Values) (map[string]map[string]interface{}, error) {
	v.Set("client_id", p.ClientKey)
	v.Set("client_secret", p.Secret)
	req, err := http.NewRequest("POST", TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	r, err := p.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	var objmap map[string]map[string]interface{}

	err = json.Unmarshal(body, &objmap)

	if err != nil {
		return nil, err
	}
	return objmap, nil
}

// CondVal convert string in string array
func CondVal(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// UnmarshalSession wil unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}
